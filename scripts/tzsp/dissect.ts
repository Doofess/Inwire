/**
 * TZSP against the reference, row for row - the header, every option, and the
 * mirrored frame inside it.
 *
 *   npx tsx scripts/tzsp/dissect.ts
 *
 * TZSP is how a MikroTik router (its packet sniffer, or a firewall rule's
 * `sniff-tzsp` action) streams the frames it forwards to a collector on
 * UDP 37008 - the cheapest way to see a whole network from one PC. Neither
 * fixture holds any, so the datagrams are built here byte by byte, with the
 * mirrored frames being the traffic a router actually forwards: a TCP
 * handshake, a DNS query, ARP, a VLAN-tagged frame, IPv6.
 *
 * Compared are every TZSP row AND, in every layer around them - the outer
 * IP/UDP that carried the datagram and the inner frame's own - the rows that
 * say which packet it is (addresses, ports, lengths, the TCP stream and
 * flags, ARP whole), because a tunnel that reads its header right and its
 * payload at the wrong offset is the failure worth catching. Their other rows
 * carry this build's formatting of IP and Ethernet, which differs from the
 * reference by design on every frame and is `tree-coverage.ts`'s to record. The inner TCP handshake spans two datagrams, so the
 * TCP analysis is held across the tunnel too.
 *
 * Not compared, each said where it is built:
 *  - an 802.11 frame, which the reference dissects and this build keeps as
 *    bytes;
 *  - the Time Stamp option's value, a local time whose zone the reference
 *    names from Windows ("Jerusalem Standard Time") and this build from the
 *    browser's locale data ("Israel Standard Time"); its date is checked here.
 */
import { Bytes, internetChecksum, ipv4, udp, udpFrameTo } from '../parity/synthetic';
import { fieldValue } from '../../src/services/dissect/fieldAccess';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';

const ROUTER = '192.168.88.1';
const COLLECTOR = '192.168.88.10';

/** A TZSP datagram from the router to the collector. */
const tzsp = (type: number, encap: number, options: number[], frame: Uint8Array | number[] = []) =>
  udpFrameTo(ROUTER, COLLECTOR, 37008, 37008, Uint8Array.from([1, type, encap >> 8, encap & 0xff, ...options, ...frame]));
/** A received Ethernet frame with no options but End - what MikroTik sends. */
const mirrored = (frame: Uint8Array) => tzsp(0, 1, [1], frame);

const MAC_A = '02:00:00:00:00:0a';
const MAC_B = '02:00:00:00:00:0b';
const ethernet = (dst: string, src: string, etherType: number, payload: Uint8Array | number[]) =>
  Uint8Array.from([...new Bytes().mac(dst).mac(src).u16(etherType).build(), ...payload]);

/** A TCP segment with a correct header length; flags as given, checksum zero. */
const tcp = (srcPort: number, dstPort: number, seq: number, ack: number, flags: number) =>
  new Bytes().u16(srcPort, dstPort).u32(seq).u32(ack).u8(0x50, flags).u16(64240, 0, 0).build();
const tcpFrame = (src: string, dst: string, segment: Uint8Array, from = MAC_A, to = MAC_B) =>
  ethernet(to, from, 0x0800, ipv4(6, segment, src, dst));

/** A DNS query for example.com, A. */
const dnsQuery = new Bytes().u16(0x1234, 0x0100, 1, 0, 0, 0)
  .u8(7).ascii('example').u8(3).ascii('com').u8(0).u16(1, 1).build();

const arpRequest = new Bytes().u16(1, 0x0800).u8(6, 4).u16(1)
  .mac(MAC_A).ipv4('10.1.1.1').mac('00:00:00:00:00:00').ipv4('10.1.1.254').build();

/** An ICMP echo request with a correct checksum. */
function icmpEcho(id: number, seq: number): Uint8Array {
  const b = new Bytes().u8(8, 0).u16(0).u16(id, seq).ascii('abcdefgh').build();
  let sum = 0;
  for (let i = 0; i < b.length; i += 2) sum += (b[i] << 8) | (b[i + 1] ?? 0);
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  const c = ~sum & 0xffff;
  b[2] = c >> 8;
  b[3] = c & 0xff;
  return b;
}

/** An IPv6 header around a UDP datagram, with the checksum IPv6 requires. */
const ipv6Udp = (payload: Uint8Array) => {
  const src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a];
  const dst = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb];
  const datagram = udp(40000, 9999, payload);
  const pseudo = Uint8Array.from([...src, ...dst, 0, 0, datagram.length >> 8, datagram.length & 0xff, 0, 0, 0, 17, ...datagram]);
  const sum = internetChecksum(pseudo);
  datagram[6] = sum >> 8;
  datagram[7] = sum & 0xff;
  return new Bytes().u32(0x60000000).u16(datagram.length).u8(17, 255).raw(src).raw(dst).raw(datagram).build();
};

/** Every option tshark names, with values set. The FCS one marks the heading. */
const EVERY_OPTION = [
  0, 0,
  10, 1, 0xd0, // signal -48
  11, 1, 0xa0, // silence -96
  12, 1, 108, // 54 Mbit/s
  13, 4, 1, 2, 3, 4,
  14, 1, 1, // RFC1042 encoded
  15, 1, 1, 16, 1, 1, 17, 1, 1,
  18, 1, 6,
  40, 4, 0, 0, 0, 7,
  41, 2, 0, 60,
  60, 6, 0x02, 0x5e, 0x0c, 0x11, 0x22, 0x33,
  80, 7, ...[...'hAP-ac2'].map((c) => c.charCodeAt(0)),
  81, 6, ...[...'Office'].map((c) => c.charCodeAt(0)),
  83, 2, 0x69, 0x6a,
  84, 4, 0, 0, 1, 0,
  99, 2, 9, 9,
  1,
];
/** The same flags clear, and values the reference has no name for. */
const PLAIN_OPTIONS = [
  12, 1, 7, // a rate nobody names
  14, 1, 9, // a message type nobody names
  15, 1, 0, 16, 1, 0, 17, 1, 0,
  18, 1, 100, // a channel outside the table
  18, 1, 149, 18, 1, 36, 18, 1, 14, 18, 1, 195,
  18, 2, 0, 11, // a two-byte channel
  10, 2, 0xd0, 0, // a two-byte signal
  10, 1, 0x20, // a positive signal
  41, 2, 0xff, 0xff, // a negative original length
  80, 0, // an empty string
  1,
];
const TIMESTAMP_OPTIONS = [82, 4, 0x65, 0x5f, 0x2a, 0x10, 1];
/**
 * A sensor with MikroTik's OUI. The reference run with `-n` shows the bare
 * address; this build names the vendor beside it, as it does for every MAC
 * (`eth.src` included), so that row is checked here rather than compared.
 */
const MIKROTIK_SENSOR = [60, 6, 0x4c, 0x5e, 0x0c, 0x11, 0x22, 0x33, 1];

const SYN = tcp(51000, 443, 1000, 0, 0x02);
const SYN_ACK = tcp(443, 51000, 5000, 1001, 0x12);

const cases: OracleCase[] = [
  // The traffic a router mirrors.
  { label: 'a mirrored TCP SYN reports the inner hosts', frame: mirrored(tcpFrame('10.1.1.1', '10.2.2.2', SYN)) },
  { label: 'its SYN-ACK, through the same tunnel', frame: mirrored(tcpFrame('10.2.2.2', '10.1.1.1', SYN_ACK, MAC_B, MAC_A)) },
  { label: 'a mirrored DNS query', frame: mirrored(ethernet(MAC_B, MAC_A, 0x0800, ipv4(17, udp(53001, 53, dnsQuery), '10.1.1.1', '10.1.1.53'))) },
  { label: 'a mirrored ARP request reports the inner MACs', frame: mirrored(ethernet('ff:ff:ff:ff:ff:ff', MAC_A, 0x0806, arpRequest)) },
  {
    label: 'a mirrored VLAN-tagged ping',
    frame: mirrored(ethernet(MAC_B, MAC_A, 0x8100, [0x20, 0x0a, 0x08, 0x00, ...ipv4(1, icmpEcho(0x77, 1), '10.9.9.1', '10.9.9.2')])),
  },
  { label: 'a mirrored IPv6 frame', frame: mirrored(ethernet('33:33:00:00:00:fb', MAC_A, 0x86dd, ipv6Udp(Uint8Array.from([1, 2, 3, 4])))) },
  { label: 'a mirrored ethertype nothing reads', frame: mirrored(ethernet(MAC_B, MAC_A, 0x9999, [1, 2, 3, 4, 5, 6, 7, 8])) },
  // The options.
  { label: 'every option, the FCS error marking the heading', frame: tzsp(0, 1, EVERY_OPTION, tcpFrame('10.3.3.3', '10.4.4.4', tcp(40000, 80, 1, 0, 0x02))) },
  { label: 'the flags clear, and values nobody names', frame: tzsp(0, 1, PLAIN_OPTIONS, tcpFrame('10.5.5.5', '10.6.6.6', tcp(40001, 80, 1, 0, 0x02))) },
  {
    label: 'a sensor named by its vendor',
    frame: tzsp(0, 1, MIKROTIK_SENSOR, tcpFrame('10.15.0.1', '10.15.0.2', tcp(40007, 22, 1, 0, 0x02))),
    notCompared: 'the sensor MAC is drawn with its vendor, which the reference run with -n does not',
  },
  { label: 'a capture time stamp', frame: tzsp(0, 1, TIMESTAMP_OPTIONS, tcpFrame('10.7.7.7', '10.8.8.8', tcp(40002, 80, 1, 0, 0x02))) },
  // Encapsulations and types.
  { label: 'a raw IP frame', frame: tzsp(0, 7, [1], ipv4(17, udp(1234, 5678, Uint8Array.from([9, 9])), '10.10.10.1', '10.10.10.2')) },
  { label: 'a frame for transmit', frame: tzsp(1, 1, [1], tcpFrame('10.11.0.1', '10.11.0.2', tcp(40003, 22, 1, 0, 0x02))) },
  { label: 'a configuration message', frame: tzsp(3, 1, [1], tcpFrame('10.12.0.1', '10.12.0.2', tcp(40004, 22, 1, 0, 0x02))) },
  { label: 'a type nobody names', frame: tzsp(2, 1, [1], tcpFrame('10.13.0.1', '10.13.0.2', tcp(40005, 22, 1, 0, 0x02))) },
  { label: 'a keepalive carries nothing', frame: tzsp(4, 1, []) },
  { label: 'a port opener carries nothing', frame: tzsp(5, 1, []) },
  { label: 'an encapsulation nobody names', frame: tzsp(0, 999, [1], [1, 2, 3]) },
  { label: 'an encapsulation named but not read (SLIP)', frame: tzsp(0, 3, [1], [0xc0, 1, 2, 0xc0]) },
  {
    label: 'an 802.11 frame, kept as bytes',
    frame: tzsp(0, 18, [1], [0x08, 0x02, 0, 0, ...new Array(20).fill(0x11)]),
    notCompared: 'the reference dissects 802.11, which this build does not read',
  },
  // Cut short, and not TZSP at all.
  { label: 'a header cut after the version', frame: udpFrameTo(ROUTER, COLLECTOR, 37008, 37008, Uint8Array.from([1])) },
  { label: 'a header cut inside the encapsulation', frame: udpFrameTo(ROUTER, COLLECTOR, 37008, 37008, Uint8Array.from([1, 0, 0])) },
  { label: 'options with no End', frame: tzsp(0, 1, [0, 0, 10, 1]) },
  { label: 'an inner frame too short to be Ethernet', frame: tzsp(0, 1, [1], [5, 5, 5]) },
  { label: 'a version 2 header is read as version 1', frame: udpFrameTo(ROUTER, COLLECTOR, 37008, 37008, Uint8Array.from([2, 0, 0, 1, 1, ...tcpFrame('10.14.0.1', '10.14.0.2', tcp(40006, 22, 1, 0, 0x02))])) },
  {
    label: 'a datagram on 37008 that is not TZSP',
    frame: udpFrameTo(ROUTER, COLLECTOR, 50000, 37008, new TextEncoder().encode('hello, world')),
  },
];

// `tcp.stream` and `tcp.len` sit at another place in this build's TCP layer
// than in the reference's, so the stream is checked across the tunnel below;
// `vlan.etype` is written `0x0800 (IPv4)` on every VLAN frame, by design.
const ROWS = new RegExp(`^(${[
  'tzsp\.(?!time_stamp)', 'vlan\.id$', 'ip\.(src|dst|proto|len)$', 'ipv6\.(src|dst|nxt|plen)$',
  'tcp\.(srcport|dstport|flags)$', 'udp\.(srcport|dstport|length)$', 'arp\.', 'icmp\.(type|code|ident|seq)$',
  'dns\.qry\.name$', 'data\.',
].join('|')})`);
const packets = await compareWithReference(cases, { rows: ROWS });
await checkRevisit(cases);

const at = (label: string) => packets[cases.findIndex((c) => c.label === label)];
const syn = at('a mirrored TCP SYN reports the inner hosts');
check('a mirrored frame names TZSP between the two UDP layers and the inner frame',
  syn?.frameProtocols?.join(':') === 'frame:eth:ip:udp:tzsp:eth:ip:tcp', syn?.frameProtocols?.join(':'));
check('the inner hosts are the columns', syn?.source === '10.1.1.1' && syn?.destination === '10.2.2.2',
  `${syn?.source} -> ${syn?.destination}`);
check('the header keys are filterable', syn !== undefined && fieldValue(syn, 'tzsp.encap') === 1 && fieldValue(syn, 'tzsp.type') === 0);
check('the outer frame keeps its own Ethernet source in the bag',
  syn !== undefined && String(fieldValue(syn, 'eth.src')) === '00:00:5e:00:53:01', syn && String(fieldValue(syn, 'eth.src')));
const synAck = at('its SYN-ACK, through the same tunnel');
check('the inner handshake is one TCP stream across two datagrams',
  syn?.streamId !== undefined && synAck?.streamId === syn.streamId, `${syn?.streamId} / ${synAck?.streamId}`);
const tzspLayer = (label: string) => at(label)?.layers.find((l) => l.name === 'Tazmen Sniffer Protocol');
check('the inner Ethernet header points at its own bytes in the frame',
  JSON.stringify(syn?.layers.filter((l) => l.name === 'Ethernet II')[1]?.rawBytesRange) === JSON.stringify([47, 60]),
  JSON.stringify(syn?.layers.filter((l) => l.name === 'Ethernet II')[1]?.rawBytesRange));
const stamp = tzspLayer('a capture time stamp')?.fields.find((f) => f.abbrev === 'tzsp.time_stamp')?.value;
check('the time stamp is drawn as a date, in November 2023', /^Nov 2[34], 2023 /.test(String(stamp)), String(stamp));
const sensor = tzspLayer('a sensor named by its vendor')?.fields.find((f) => f.abbrev === 'tzsp.sensormac')?.value;
check('a MikroTik sensor is named by its vendor', sensor === 'Routerboardc_11:22:33 (4c:5e:0c:11:22:33)', String(sensor));
const wifi = at('an 802.11 frame, kept as bytes');
check('an 802.11 frame reads as TZSP, named, with its bytes as data',
  wifi?.protocolLabel === 'TZSP' && wifi?.info === 'IEEE 802.11' && wifi?.layers.at(-1)?.name === 'Data',
  `${wifi?.protocolLabel} | ${wifi?.info} | ${wifi?.layers.at(-1)?.name}`);
finish('TZSP');
