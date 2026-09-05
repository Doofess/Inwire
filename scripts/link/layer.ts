/**
 * Assertion tests for the link layer.
 *
 *   npx tsx scripts/link/layer.ts
 *
 * Until Phase 6 the capture file's declaration of what its frames are - the
 * pcap header's `network` field, the pcapng IDB's `LinkType` - was parsed and
 * then ignored, and every frame was decoded as Ethernet II with the network
 * header at offset 14. On the captures this app takes itself that is always
 * right, which is exactly why it went unnoticed.
 *
 * The property under test is the one that failure hides: **the same datagram,
 * wrapped in any of the five link layers, must dissect to the same packet.**
 * A test that only checked "SLL parses" would pass on an implementation that
 * read the addresses from the wrong offset, because the bytes it read would
 * still be *some* addresses.
 *
 * The second half covers 802.3/LLC, which is not exotic at all: every STP BPDU
 * on the wire is one, and this repo's own fixture has 105 of them. Their
 * type/length field was being read as an ethertype, and the STP dissector
 * reached past an LLC header that nothing described - so the tree jumped from
 * Ethernet straight to Spanning Tree and `frameProtocols` never said `llc`.
 */
import { LINKTYPE } from '../../src/services/dissect/types';
import { dissectLinkLayer } from '../../src/services/dissectors/linkLayer';
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';

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

// --- one datagram, five wrappers ---------------------------------------------

/** An IPv4/TCP datagram: 10.0.0.1:51000 -> 93.184.216.34:443, SYN. */
function datagram(): number[] {
  const tcp = [
    0xc7, 0x38, 0x01, 0xbb,              // 51000 -> 443
    0x00, 0x00, 0x03, 0xe8,              // seq
    0x00, 0x00, 0x00, 0x00,              // ack
    0x50, 0x02, 0x20, 0x00,              // offset 5, SYN, window
    0x00, 0x00, 0x00, 0x00,              // checksum, urgent
  ];
  const total = 20 + tcp.length;
  return [
    0x45, 0x00, (total >> 8) & 0xff, total & 0xff,
    0x00, 0x01, 0x40, 0x00,
    0x40, 0x06, 0x00, 0x00,
    10, 0, 0, 1,
    93, 184, 216, 34,
    ...tcp,
  ];
}

const MAC_DST = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAC_SRC = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

const WRAPPED: { name: string; linktype: number; bytes: number[] }[] = [
  {
    name: 'Ethernet II',
    linktype: LINKTYPE.ETHERNET,
    bytes: [...MAC_DST, ...MAC_SRC, 0x08, 0x00, ...datagram()],
  },
  {
    name: 'raw IP (no link layer at all)',
    linktype: LINKTYPE.RAW_IP,
    bytes: datagram(),
  },
  {
    name: 'BSD loopback (4-byte address family)',
    linktype: LINKTYPE.NULL,
    bytes: [0x02, 0x00, 0x00, 0x00, ...datagram()],
  },
  {
    name: 'Linux cooked v1 (16-byte pseudo-header)',
    linktype: LINKTYPE.LINUX_SLL,
    bytes: [
      0x00, 0x00,                        // packet type: unicast to us
      0x00, 0x01,                        // ARPHRD: Ethernet
      0x00, 0x06,                        // address length
      ...MAC_SRC, 0x00, 0x00,            // address, padded to 8
      0x08, 0x00,                        // protocol
      ...datagram(),
    ],
  },
  {
    name: 'Linux cooked v2 (20-byte pseudo-header)',
    linktype: LINKTYPE.LINUX_SLL2,
    bytes: [
      0x08, 0x00,                        // protocol
      0x00, 0x00,                        // reserved
      0x00, 0x00, 0x00, 0x03,            // interface index
      0x00, 0x01,                        // ARPHRD: Ethernet
      0x00,                              // packet type
      0x06,                              // address length
      ...MAC_SRC, 0x00, 0x00,            // address, padded to 8
      ...datagram(),
    ],
  },
];

for (const { name, linktype, bytes } of WRAPPED) {
  const raw = new Uint8Array(bytes);
  const { packet } = decodeRawEthernetPacket(
    raw, 1, 1_700_000_000_000_000, 0, 0, raw.length,
    undefined, undefined, undefined, undefined, undefined, linktype,
  );
  check(`${name}: the datagram is found`,
    [packet.source, packet.destination, packet.sourcePort, packet.destPort],
    ['10.0.0.1', '93.184.216.34', 51000, 443]);
  check(`${name}: ...and dissected to the same layers`,
    packet.frameProtocols?.filter((t) => t === 'ip' || t === 'tcp'), ['ip', 'tcp']);
  check(`${name}: ...with the TTL off the wire, not off the wrapper`,
    packet.fields?.['ip.ttl'], 64);
}

// Decoded as Ethernet, a cooked capture reads the IP header six bytes early -
// which is not a parse failure, it is a different and entirely wrong packet.
// This is the bug the link type exists to prevent, stated as a test.
{
  const sll = new Uint8Array(WRAPPED[3].bytes);
  const asEthernet = decodeRawEthernetPacket(
    sll, 1, 1_700_000_000_000_000, 0, 0, sll.length,
    undefined, undefined, undefined, undefined, undefined, LINKTYPE.ETHERNET,
  ).packet;
  checkTrue('a cooked capture decoded as Ethernet does NOT yield the real addresses',
    asEthernet.source !== '10.0.0.1' || asEthernet.destination !== '93.184.216.34');
}

// --- the link layer's own reading ---------------------------------------------

{
  const eth = dissectLinkLayer(new Uint8Array(WRAPPED[0].bytes), LINKTYPE.ETHERNET);
  check('Ethernet: the network layer starts at 14', eth.l3Offset, 14);
  check('...both MACs are read', [eth.srcMac, eth.dstMac],
    ['66:77:88:99:aa:bb', '00:11:22:33:44:55']);
  check('...and the encapsulation is named for the Frame layer', eth.encapsulation, 'Ethernet (1)');

  const raw = dissectLinkLayer(new Uint8Array(WRAPPED[1].bytes), LINKTYPE.RAW_IP);
  check('raw IP: nothing precedes the datagram', raw.l3Offset, 0);
  check('...and it has no link-layer rows to show', raw.layers.length, 0);
  check('...its family comes from the version nibble, since nothing declares it',
    raw.etherType, 0x0800);

  // The same, for IPv6: there is no other way to tell.
  const raw6 = dissectLinkLayer(new Uint8Array([0x60, 0, 0, 0, 0, 0, 59, 64]), LINKTYPE.RAW_IP);
  check('raw IPv6 is recognised from the same nibble', raw6.etherType, 0x86dd);

  const sll = dissectLinkLayer(new Uint8Array(WRAPPED[3].bytes), LINKTYPE.LINUX_SLL);
  check('cooked v1: the network layer starts at 16', sll.l3Offset, 16);
  check('...and the header names a source but no destination',
    [sll.srcMac, sll.dstMac], ['66:77:88:99:aa:bb', undefined]);

  const sll2 = dissectLinkLayer(new Uint8Array(WRAPPED[4].bytes), LINKTYPE.LINUX_SLL2);
  check('cooked v2: the network layer starts at 20', sll2.l3Offset, 20);
}

// A truncated link layer must say so rather than reading past the end.
for (const [label, linktype, length] of [
  ['Ethernet', LINKTYPE.ETHERNET, 8],
  ['cooked v1', LINKTYPE.LINUX_SLL, 10],
  ['cooked v2', LINKTYPE.LINUX_SLL2, 12],
  ['loopback', LINKTYPE.NULL, 2],
] as [string, number, number][]) {
  const short = dissectLinkLayer(new Uint8Array(length), linktype);
  checkTrue(`a truncated ${label} header is reported, not read past`, short.truncated);
}

// --- 802.3 / LLC / SNAP ---------------------------------------------------------

{
  // An STP BPDU: a length rather than an ethertype, then DSAP/SSAP 0x42.
  const bpdu = [
    0x00, 0x00,             // protocol identifier
    0x00, 0x00,             // version, BPDU type: configuration
    0x00,                   // flags
    0x80, 0x00, ...MAC_SRC, // root id
    0x00, 0x00, 0x00, 0x04, // root path cost
    0x80, 0x00, ...MAC_SRC, // bridge id
    0x80, 0x01,             // port id
    0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x0f, 0x00,
  ];
  const frame = new Uint8Array([
    0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, ...MAC_SRC,
    0x00, bpdu.length + 3,   // 802.3 length
    0x42, 0x42, 0x03,        // LLC: DSAP, SSAP, UI control
    ...bpdu,
  ]);

  const link = dissectLinkLayer(frame, LINKTYPE.ETHERNET);
  check('an 802.3 length is not mistaken for an ethertype', link.etherType <= 1500, true);
  check('...the LLC header is read', [link.llcOffset, link.llcDsap], [14, 0x42]);
  check('...and shown as a layer of its own', link.layers.map((l) => l.name),
    ['Ethernet II', 'Logical-Link Control']);
  // Wireshark shows bytes 12-13 of an 802.3 frame as a Length row. Calling it
  // "Type: 0x0027 (Unknown)" is a straightforwardly wrong reading of the wire.
  check('...and bytes 12-13 are labelled a length, not a type',
    link.layers[0].fields.map((f) => f.name).filter((n) => n === 'Length' || n === 'Type'),
    ['Length']);
  check('...with no eth.type published, because there is no type',
    'eth.type' in link.fields, false);

  const { packet } = decodeRawEthernetPacket(
    frame, 1, 1_700_000_000_000_000, 0, 0, frame.length,
    undefined, undefined, undefined, undefined, undefined, LINKTYPE.ETHERNET,
  );
  check('the BPDU still dissects, from its own LLC offset',
    packet.frameProtocols, ['frame', 'eth', 'llc', 'stp']);
  check('...and says what it is', packet.protocolLabel, 'STP');
}

{
  // SNAP: DSAP/SSAP 0xAA and a UI control byte, then an OUI and the real
  // ethertype - which is how IPv4 rides over 802.3 and over 802.11.
  const payload = datagram();
  const frame = new Uint8Array([
    ...MAC_DST, ...MAC_SRC,
    0x00, payload.length + 8,
    0xaa, 0xaa, 0x03,             // LLC
    0x00, 0x00, 0x00,             // OUI: encapsulated Ethernet
    0x08, 0x00,                   // ethertype: IPv4
    ...payload,
  ]);

  const link = dissectLinkLayer(frame, LINKTYPE.ETHERNET);
  check('SNAP hands back the real ethertype', link.etherType, 0x0800);
  check('...and the network layer starts past both headers', link.l3Offset, 22);
  check('...and the OUI is published', link.fields['llc.oui'], 0);

  const { packet } = decodeRawEthernetPacket(
    frame, 1, 1_700_000_000_000_000, 0, 0, frame.length,
    undefined, undefined, undefined, undefined, undefined, LINKTYPE.ETHERNET,
  );
  check('an IPv4 datagram inside SNAP is the same datagram',
    [packet.source, packet.destination, packet.destPort],
    ['10.0.0.1', '93.184.216.34', 443]);
  check('...and the LLC layer sits between Ethernet and IP',
    packet.frameProtocols, ['frame', 'eth', 'llc', 'ip', 'tcp']);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All link-layer checks passed.');
process.exit(0);
