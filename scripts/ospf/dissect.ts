/**
 * OSPF, against tshark.
 *
 *   npx tsx scripts/ospf/dissect.ts
 *
 * The Info line is only the packet type, so the columns are quickly checked
 * and most of the value here is in what the Hello carries: the **neighbour
 * list**, which is what diagnoses a one-way link. A router that does not
 * appear in its neighbour's Hello is not being heard, and the Hellos it is
 * sending prove nothing about that.
 *
 * The header declares its own length and the packet is not padded to it, so a
 * Hello with three neighbours and one with none differ only in that field -
 * which makes a length that is read but not enforced invisible until a packet
 * arrives with something after it.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { dissectOspf } from '../../src/services/dissectors/ospf';
import {
  Bytes, check, failureCount, internetChecksum, ipFrame, runCases, type SyntheticCase,
} from '../parity/synthetic';

/** An OSPFv2 header wrapping a body, with the checksum filled in. */
function ospf(type: number, body: Uint8Array, routerId = '192.0.2.1', areaId = '0.0.0.0'):
  Uint8Array {
  const bytes = new Bytes()
    .u8(2, type)
    .u16(24 + body.length)
    .ipv4(routerId).ipv4(areaId)
    .u16(0).u16(0)      // checksum, autype
    .zeros(8)           // authentication
    .raw(body)
    .build();
  const sum = internetChecksum(bytes);
  bytes[12] = (sum >> 8) & 0xff;
  bytes[13] = sum & 0xff;
  return bytes;
}

function hello(neighbours: string[] = [], designated = '0.0.0.0'): Uint8Array {
  const b = new Bytes()
    .ipv4('255.255.255.0')
    .u16(10)            // hello interval
    .u8(0x02, 1)        // options, router priority
    .u32(40)            // dead interval
    .ipv4(designated).ipv4('0.0.0.0');
  for (const neighbour of neighbours) b.ipv4(neighbour);
  return b.build();
}

const dbDescription = new Bytes().u16(1500).u8(0x02, 0x07).u32(1000).build();
const lsRequest = new Bytes().u32(1).ipv4('192.0.2.5').ipv4('192.0.2.1').build();
const lsUpdate = new Bytes().u32(0).build();
const lsAck = new Bytes()
  .u16(3600).u8(0x02, 1).ipv4('192.0.2.5').ipv4('192.0.2.1')
  .u32(0x80000001).u16(0).u16(48).build();

const cases: SyntheticCase[] = [
  { name: 'a Hello with no neighbours', frame: ipFrame(89, ospf(1, hello())) },
  { name: 'a Hello naming one neighbour', frame: ipFrame(89, ospf(1, hello(['192.0.2.2']))) },
  { name: 'a Hello naming three neighbours',
    frame: ipFrame(89, ospf(1, hello(['192.0.2.2', '192.0.2.3', '192.0.2.4']))) },
  { name: 'a Hello with a designated router elected',
    frame: ipFrame(89, ospf(1, hello(['192.0.2.2'], '192.0.2.1'))) },
  { name: 'a database description', frame: ipFrame(89, ospf(2, dbDescription)) },
  { name: 'a link-state request', frame: ipFrame(89, ospf(3, lsRequest)) },
  { name: 'a link-state update', frame: ipFrame(89, ospf(4, lsUpdate)) },
  { name: 'a link-state acknowledgement', frame: ipFrame(89, ospf(5, lsAck)) },
  // A non-backbone area, so the area id is read rather than assumed zero.
  { name: 'a Hello in a non-backbone area',
    frame: ipFrame(89, ospf(1, hello(), '10.0.0.1', '0.0.0.7')) },
];

async function main(): Promise<void> {
  await runCases(cases);

  // --- the neighbour list ---------------------------------------------------------
  //
  // The half of a Hello that says whether the link is working in both
  // directions. A dissector that stops at the fixed body reports a Hello
  // identical to one with no neighbours at all.
  const threeNeighbours = ospf(1, hello(['192.0.2.2', '192.0.2.3', '192.0.2.4']));
  const read = dissectOspf(threeNeighbours, 0, threeNeighbours.length);
  check('every neighbour is counted', read?.fields['ospf.hello.neighbor_count'], 3);
  const helloNode = read?.layer.fields.find((f) => f.name === 'OSPF Hello Packet');
  const listed = (helloNode?.children ?? []).filter((f) => f.name === 'Active Neighbor');
  check('...and each is a row', listed.map((f) => f.value),
    ['192.0.2.2', '192.0.2.3', '192.0.2.4']);
  const noNeighbours = ospf(1, hello());
  check('a Hello with none says so',
    dissectOspf(noNeighbours, 0, noNeighbours.length)?.fields['ospf.hello.neighbor_count'], 0);

  // --- the header's own length is enforced ------------------------------------------
  const overlong = ospf(1, hello());
  overlong[2] = 0x01; overlong[3] = 0x00;
  check('a length past the packet is declined', dissectOspf(overlong, 0, overlong.length), null);
  const undersize = ospf(1, hello());
  undersize[2] = 0; undersize[3] = 8;
  check('...and one under the header size', dissectOspf(undersize, 0, undersize.length), null);

  // --- what is not OSPFv2 ------------------------------------------------------------
  //
  // v3 carries IPv6 topology in a differently shaped header. Half-reading it
  // would put v2's field names on v3's bytes, which is worse than declining.
  const v3 = ospf(1, hello());
  v3[0] = 3;
  check('OSPFv3 is declined rather than half-read', dissectOspf(v3, 0, v3.length), null);
  const badType = ospf(1, hello());
  badType[1] = 9;
  check('an unknown packet type is declined', dissectOspf(badType, 0, badType.length), null);
  check('a header alone is not a packet', dissectOspf(threeNeighbours, 0, 20), null);

  // --- what reaches the rest of the app -----------------------------------------------
  const frame = ipFrame(89, ospf(1, hello(['192.0.2.2']), '10.0.0.1', '0.0.0.7'));
  const { packet } = decodeRawEthernetPacket(frame, 1, 1_700_000_000_000_000, 0, 0, frame.length);
  check('the protocol chain is right', packet.frameProtocols, ['frame', 'eth', 'ip', 'ospf']);
  check('the source router is published', packet.fields?.['ospf.srcrouter'], '10.0.0.1');
  check('the area is published', packet.fields?.['ospf.area_id'], '0.0.0.7');
  check('the dead interval is published', packet.fields?.['ospf.hello.router_dead_interval'], 40);

  console.log();
  if (failureCount() > 0) {
    console.log(`${failureCount()} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All OSPF checks passed.');
  process.exit(0);
}

main();
