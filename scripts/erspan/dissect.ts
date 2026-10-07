/**
 * ERSPAN against the reference, row for row.
 *
 *   npx tsx scripts/erspan/dissect.ts
 *
 * A switch that mirrors a port to an IP address (Cisco, Arista, Juniper,
 * Linux, the clouds' traffic mirroring) sends every copied frame inside IP,
 * GRE and an ERSPAN header, which is how one machine sees a whole network's
 * traffic without a hub, a tap or a mirror port of its own. Neither fixture
 * holds any, so the frames are built in `frames.ts` from the header layouts
 * in draft-foschiano-erspan: types I, II and III, the platform subheaders
 * that type III can carry, every frame type and granularity, and the cut
 * headers the reference marks as malformed.
 *
 * What is compared: Protocol, Info, and every `gre.`, `erspan.`, `vlan.`
 * and `data.` row, plus both Ethernet layers' stream indexes - the outer
 * one, from the switch, and the mirrored one inside it. Not their address
 * rows, which name a vendor here and not in the reference, by design; the
 * mirrored pair is checked below instead. The inner packet's own rows (IP,
 * TCP, UDP, ARP) are the same code as an outer packet's and are held by
 * their own suites.
 */
import { internetChecksum, ipv4 } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';
import { arpRequest, erspanFrame, erspanFrame6, gre, icmpEcho, mirrored, tcpSyn, typeII, typeIII, udp6 } from './frames';

const echo = (seq: number) => mirrored(0x0800, ipv4(1, icmpEcho(1, seq), '10.9.0.10', '10.9.0.20'));

/** GRE with the checksum bit and a checksum the frame does or does not deserve. */
function greChecksummed(protocol: number, body: number[], correct: boolean): number[] {
  const bytes = [0x80, 0x00, protocol >> 8, protocol & 255, 0, 0, 0, 0, ...body];
  const sum = correct ? internetChecksum(Uint8Array.from(bytes)) : 0x1234;
  bytes[4] = sum >> 8;
  bytes[5] = sum & 255;
  return bytes;
}

/** A type III header with every field at its widest. */
const everyBit = (platform: [number, number]) => typeIII({
  session: 1023, timestamp: 0xfedcba98, cos: 7, bso: 3, vlan: 4095, truncated: true, sgt: 0xffff,
  p: true, ft: 0, hw: 63, d: true, gra: 1, platform,
});
const subheader = (id: number) => everyBit([((id << 26) | 0x2aaaaaa) >>> 0, 0x89abcdef]);

const cases: OracleCase[] = [
  // Type I: no header, the mirrored frame straight after GRE.
  { label: 'type I', frame: erspanFrame(gre({ protocol: 0x88be }), echo(1)) },
  { label: 'type I behind a GRE key', frame: erspanFrame(gre({ protocol: 0x88be, key: 77 }), echo(2)) },
  // Type II: the common one.
  { label: 'type II carrying a TCP SYN', frame: erspanFrame(gre({ protocol: 0x88be, seq: 5 }), [...typeII({ session: 100, index: 7 }), ...mirrored(0x0800, tcpSyn('10.9.0.10', '10.9.0.20'))]) },
  {
    label: 'type II with a VLAN, a class of service, 802.1Q and truncation',
    frame: erspanFrame(gre({ protocol: 0x88be, seq: 6 }), [...typeII({ vlan: 42, cos: 5, encap: 2, truncated: true, session: 1023, index: 0xfffff, reserved: 0xabc }), ...echo(3)]),
  },
  { label: 'type II, originally ISL', frame: erspanFrame(gre({ protocol: 0x88be, seq: 7 }), [...typeII({ session: 9, encap: 1 }), ...echo(4)]) },
  { label: 'type II, VLAN tag preserved', frame: erspanFrame(gre({ protocol: 0x88be, seq: 8 }), [...typeII({ session: 9, encap: 3 }), ...echo(5)]) },
  { label: 'type II mirroring a VLAN-tagged frame', frame: erspanFrame(gre({ protocol: 0x88be, seq: 9 }), [...typeII({ session: 1 }), ...mirrored(0x0800, ipv4(1, icmpEcho(1, 6), '10.9.0.10', '10.9.0.20'), 300)]) },
  { label: 'type II mirroring an ARP request', frame: erspanFrame(gre({ protocol: 0x88be, seq: 10 }), [...typeII({ session: 1 }), ...mirrored(0x0806, arpRequest())]) },
  { label: 'type II over IPv6', frame: erspanFrame6(gre({ protocol: 0x88be, seq: 11 }), [...typeII({ session: 2 }), ...echo(7)]) },
  // GRE's checksum covers its payload, so these are written whole. Without a
  // sequence number both are type I - the second is read as one too.
  { label: 'type I behind a correct GRE checksum', frame: erspanFrame(greChecksummed(0x88be, echo(8), true), []) },
  { label: 'type I behind an incorrect GRE checksum', frame: erspanFrame(greChecksummed(0x88be, echo(19), false), []) },
  // Type III.
  {
    label: 'type III mirroring IPv6/UDP, egress, custom granularity',
    frame: erspanFrame(gre({ protocol: 0x22eb, seq: 20 }), [...typeIII({ session: 3, timestamp: 123456, sgt: 77, hw: 5, d: true, gra: 3 }), ...mirrored(0x86dd, udp6(41234, 41235, [1, 2, 3, 4]))]),
  },
  { label: 'type III with a platform 3 subheader, mirroring ARP', frame: erspanFrame(gre({ protocol: 0x22eb, seq: 21 }), [...typeIII({ session: 3, timestamp: 1, platform: [((3 << 26) | 0x1234) >>> 0, 0x99] }), ...mirrored(0x0806, arpRequest())]) },
  ...[0, 1, 2, 3, 4, 5, 6, 7, 9, 63].map((id, i): OracleCase => ({
    label: `type III, every bit set, platform ${id}`, frame: erspanFrame(gre({ protocol: 0x22eb, seq: 30 + i }), [...subheader(id), ...echo(9)]),
  })),
  { label: 'type III, Ethernet PDU bit set', frame: erspanFrame(gre({ protocol: 0x22eb, seq: 40 }), [...typeIII({ session: 3, timestamp: 2, p: true }), ...echo(10)]) },
  { label: 'type III, frame type IP: left as data', frame: erspanFrame(gre({ protocol: 0x22eb, seq: 41 }), [...typeIII({ session: 3, timestamp: 2, ft: 2 }), ...ipv4(1, icmpEcho(1, 11), '10.9.0.10', '10.9.0.20')]) },
  { label: 'type III, short frame, IEEE 1588, frame type 31', frame: erspanFrame(gre({ protocol: 0x22eb, seq: 42 }), [...typeIII({ session: 3, timestamp: 2, bso: 1, gra: 2, ft: 31 }), ...echo(12)]) },
  { label: 'type III, oversized frame, frame type 3', frame: erspanFrame(gre({ protocol: 0x22eb, seq: 43 }), [...typeIII({ session: 3, timestamp: 2, bso: 2, ft: 3 }), ...echo(13)]) },
  { label: 'type III without a GRE sequence number', frame: erspanFrame(gre({ protocol: 0x22eb }), [...typeIII({ session: 4, timestamp: 3 }), ...echo(14)]) },
  // The version nibble decides, not the GRE protocol type.
  { label: 'a type III header behind 0x88BE', frame: erspanFrame(gre({ protocol: 0x88be, seq: 50 }), [...typeIII({ session: 4, timestamp: 3 }), ...echo(15)]) },
  { label: 'a version nobody defined', frame: erspanFrame(gre({ protocol: 0x88be, seq: 51 }), [0x30, 0x00, 0, 1, 0, 0, 0, 0, ...echo(16)]) },
  { label: 'version 0 behind a sequence number', frame: erspanFrame(gre({ protocol: 0x88be, seq: 52 }), [0x00, 0x00, 0, 1, 0, 0, 0, 0, ...echo(17)]) },
  // Cut short: every field that arrived, then the reference's complaint.
  { label: 'a type II header cut after its first word', frame: erspanFrame(gre({ protocol: 0x88be, seq: 60 }), [0x10, 0x00]) },
  { label: 'a type III header cut in its first word', frame: erspanFrame(gre({ protocol: 0x22eb, seq: 61 }), [0x20, 0x00, 0x00]) },
  { label: 'a type III subheader cut short', frame: erspanFrame(gre({ protocol: 0x22eb, seq: 62 }), typeIII({ session: 3, timestamp: 2, platform: [3 << 26, 0] }).slice(0, 14)) },
  { label: 'a type II header with no frame behind it', frame: erspanFrame(gre({ protocol: 0x88be, seq: 63 }), typeII({ session: 9 })) },
  { label: 'a type II header with three bytes behind it', frame: erspanFrame(gre({ protocol: 0x88be, seq: 64 }), [...typeII({ session: 9 }), 1, 2, 3]) },
  { label: 'type I with three bytes', frame: erspanFrame(gre({ protocol: 0x88be }), [1, 2, 3]) },
  // GRE's own rows, which ERSPAN brought up to the reference's.
  { label: 'plain IP behind GRE checksum, key and sequence', frame: erspanFrame([0xb0, 0x00, 0x08, 0x00, 0x12, 0x34, 0, 0, 0, 0, 0, 9, 0, 0, 0, 3], ipv4(1, icmpEcho(1, 18), '10.9.0.10', '10.9.0.20')) },
  {
    label: 'a mirrored frame of an ethertype nobody reads',
    frame: erspanFrame(gre({ protocol: 0x88be, seq: 70 }), [...typeII({ session: 2 }), ...mirrored(0x88b5, [1, 2, 3, 4, 5, 6])]),
    notCompared: 'the reference puts an unread ethertype\'s name in Info ("Local Experimental Ethertype 1") from a table far longer than this build\'s, and "Ethernet II" only when it has no name; this build has none for 0x88b5',
  },
];

// `vlan.etype` is the one row left out: this build writes a type as
// `0x0800 (IPv4)` everywhere, where the reference writes `IPv4 (0x0800)`.
const packets = await compareWithReference(cases, { rows: /^(gre|erspan|data)\.|^vlan\.(?!etype$)|^eth\.stream$/ });
await checkRevisit(cases);

const at = (label: string) => packets[cases.findIndex((c) => c.label === label)];
const typeIIsyn = at('type II carrying a TCP SYN');
check('a mirrored frame is `erspan` in the chain, between GRE and the inner Ethernet',
  typeIIsyn?.frameProtocols?.join(':') === 'frame:eth:ip:gre:erspan:eth:ip:tcp', typeIIsyn?.frameProtocols?.join(':'));
check('the columns are the mirrored hosts, not the switch',
  typeIIsyn?.source === '10.9.0.10' && typeIIsyn?.destination === '10.9.0.20');
check('the session id is a filter field', typeIIsyn?.fields?.['erspan.spanid'] === 100);
check('the outer GRE keeps its own field bag', typeIIsyn?.fields?.['gre.sequence_number'] === 5);
const arp = at('type II mirroring an ARP request');
check('mirrored ARP shows the mirrored MACs', arp?.source === '02:00:00:00:00:0a' && arp?.protocolLabel === 'ARP', `${arp?.source} ${arp?.protocolLabel}`);
const unknown = at('a mirrored frame of an ethertype nobody reads');
check('an unread ethertype is named from its number, as an outer frame is', unknown?.protocolLabel === '0x88b5', unknown?.protocolLabel);
const tagged = at('type II mirroring a VLAN-tagged frame');
// The carrier is untagged, so the mirrored tag is the frame's only one and
// filters as Wireshark's `vlan.id` does; an outer key would keep its value.
check('a mirrored VLAN tag is drawn, and filters when the carrier has none',
  tagged?.layers.some((l) => l.name === '802.1Q Virtual LAN') === true && tagged?.fields?.['vlan.id'] !== undefined,
  String(tagged?.fields?.['vlan.id']));
const inner = tagged?.layers.filter((l) => l.name === 'Ethernet II')[1];
check('the mirrored Ethernet header\'s bytes are where they are in the frame',
  inner?.rawBytesRange?.[0] === 14 + 20 + 8 + 8, String(inner?.rawBytesRange));
const innerRows = Object.fromEntries((inner?.fields ?? []).filter((f) => f.abbrev).map((f) => [f.abbrev, String(f.value)]));
check('the mirrored frame\'s own addresses and type are its rows',
  innerRows['eth.dst'] === '02:00:00:00:00:0b' && innerRows['eth.src'] === '02:00:00:00:00:0a'
  && innerRows['eth.type'] === '0x8100 (802.1Q Virtual LAN)', JSON.stringify(innerRows));
finish('erspan');
