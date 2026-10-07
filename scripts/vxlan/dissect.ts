/**
 * VXLAN, held to tshark on frames built from RFC 7348.
 *
 *   npx tsx scripts/vxlan/dissect.ts
 *
 * The second tunnel, and what it tests is the half of `docs/decisions/0023`
 * that GRE left unspent. GRE proved `decodeNetworkLayer` can be called again at
 * a new offset; the inner frame there is a network packet, and even its
 * Transparent Ethernet Bridging case skips fourteen bytes and then **declines
 * anything that is not inner IP** (`innerNetworkStart` in `dissectors/gre.ts`).
 *
 * VXLAN cannot decline it. An overlay's ARP is not an edge case - it is how the
 * overlay learns where anything is - and ARP has no layer-3 addresses, so the
 * reference reports the inner **MACs** in the Source and Destination columns.
 * Those columns already hold the OUTER pair by the time a tunnel is reached, so
 * this is the first frame in the build where they have to be rewritten from the
 * link layer of something that is not the frame itself.
 *
 * `compareAddresses` is on for the same reason it is on for GRE: for most
 * suites the addresses are the frame builder's own constants, and for a tunnel
 * they are the entire result.
 *
 * Everything below came from asking tshark 4.6.8, and two answers were not what
 * RFC 7348 says:
 *
 *  - **Port 8472 decodes.** Linux shipped VXLAN there before IANA assigned 4789
 *    and still defaults to it.
 *  - **Port 4790 does not.** That is VXLAN-GPE, a different header.
 *  - **The I flag is ignored.** The RFC says a receiver MUST drop a frame whose
 *    VNI-valid bit is clear; the reference dissects it anyway, and so does
 *    this, because a capture is not a receiver.
 */
import {
  Bytes, ethernet, ipv4, udpFrame, internetChecksum, runCases, failureCount,
  type SyntheticCase,
} from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';

/** An ICMPv4 echo request with a correct checksum. */
function icmpEcho(id: number, seq: number): Uint8Array {
  const b = new Bytes().u8(8, 0).u16(0).u16(id, seq).ascii('abcdefgh').build();
  const sum = internetChecksum(b);
  b[2] = (sum >> 8) & 0xff;
  b[3] = sum & 0xff;
  return b;
}

const tcpSyn = new Bytes()
  .u16(51000, 443).u32(0).u32(0).u8(0x50, 0x02).u16(64240, 0, 0).build();

/**
 * The eight-byte header, written out rather than helper-ised: flags, three
 * reserved bytes, a 24-bit VNI, one reserved byte.
 */
function vxlan(vni: number, flags = 0x08): number[] {
  return [
    flags, 0, 0, 0,
    (vni >> 16) & 0xff, (vni >> 8) & 0xff, vni & 0xff,
    0,
  ];
}

/** A whole Ethernet frame, which is what a VXLAN payload always is. */
const innerFrame = (etherType: number, payload: Uint8Array): Uint8Array =>
  Uint8Array.from([...ethernet(etherType).build(), ...payload]);

const innerIcmp = innerFrame(0x0800, ipv4(1, icmpEcho(0x1234, 1), '10.1.1.1', '10.2.2.2'));
const innerTcp = innerFrame(0x0800, ipv4(6, tcpSyn, '10.1.1.1', '10.2.2.2'));

/**
 * An ARP request inside the overlay - the case GRE declines and the reason this
 * tunnel needed the ethertype dispatch rather than just an offset.
 */
const innerArp = innerFrame(0x0806, new Bytes()
  .u16(1, 0x0800).u8(6, 4).u16(1)
  .mac('02:00:00:00:00:02').ipv4('10.1.1.1')
  .mac('00:00:00:00:00:00').ipv4('10.2.2.2')
  .build());

const vx = (payload: Uint8Array, vni = 100, port = 4789, flags = 0x08): Uint8Array =>
  udpFrame(45678, port, Uint8Array.from([...vxlan(vni, flags), ...payload]));

const cases: SyntheticCase[] = [
  // The four columns the tunnel decides. The word VXLAN appears in none of them.
  { name: 'a tunnelled ICMP echo reports the inner packet', frame: vx(innerIcmp) },
  { name: 'a tunnelled TCP SYN reports the inner packet', frame: vx(innerTcp) },
  // The one GRE cannot do: no layer-3 addresses, so the columns take the inner
  // MACs - and the broadcast destination has to resolve the way the outer
  // frame's would.
  { name: 'a tunnelled ARP reports the inner MACs, not the outer ones', frame: vx(innerArp) },

  // Ports. 8472 is what a Linux host actually sends on.
  { name: 'the Linux default port decodes the same way', frame: vx(innerIcmp, 100, 8472) },

  // The VNI is not a column, so this is really checking the header length: get
  // it wrong and the inner frame is read at the wrong offset, which produces a
  // plausible wrong answer rather than a failure.
  { name: 'a different VNI moves nothing', frame: vx(innerIcmp, 0xfffffe) },
  { name: 'VNI zero is a VNI', frame: vx(innerIcmp, 0) },

  // RFC 7348 says a receiver MUST drop this. The reference reads it, and a
  // capture is not a receiver - a frame the network dropped is still one
  // somebody needs to see.
  { name: 'the VNI-valid flag being clear changes nothing', frame: vx(innerIcmp, 100, 4789, 0x00) },
];

/** The mirrored-frame reader's own cases, which only the tree can see. */
const innerTagged = Uint8Array.from([
  ...ethernet(0x8100).build(), 0x20, 0x2a, 0x08, 0x00, ...ipv4(1, icmpEcho(0x1234, 2), '10.1.1.1', '10.2.2.2'),
]);
const treeCases: OracleCase[] = [
  ...cases.map((c) => ({ label: c.name, frame: c.frame })),
  { label: 'a VLAN-tagged frame inside the overlay', frame: vx(innerTagged) },
  { label: 'an inner ethertype nobody names', frame: vx(innerFrame(0x9999, Uint8Array.from([1, 2, 3, 4]))) },
  { label: 'an inner frame cut short of its Ethernet header', frame: vx(Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8])) },
];

async function main(): Promise<void> {
  await runCases(cases, { compareAddresses: true });
  if (failureCount() > 0) process.exit(1);
  // The tree: the UDP layer that carries the overlay, the VXLAN header, and
  // the inner frame's own Ethernet rows - its tag and its conversation.
  const packets = await compareWithReference(treeCases, {
    rows: /^(udp\.(srcport|dstport|length)|vxlan\.|eth\.stream$|vlan\.(?!etype$)|arp\.)/,
  });
  await checkRevisit(treeCases);
  check('the overlay is carried by UDP, as the reference chains it',
    packets[0]?.frameProtocols?.join(':').includes('udp:vxlan:eth:ip:icmp') === true,
    packets[0]?.frameProtocols?.join(':'));
  check('the inner Ethernet header carries abbrevs, as any frame\'s does',
    packets[0]?.layers.filter((l) => l.name === 'Ethernet II')[1]?.fields.some((f) => f.abbrev === 'eth.src') === true);
  finish('VXLAN');
}

void main();
