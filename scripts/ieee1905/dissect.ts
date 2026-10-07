/**
 * IEEE 1905.1a and EasyMesh against the reference, row for row.
 *
 *   npx tsx scripts/ieee1905/dissect.ts
 *
 * The fixture holds one mesh's 1905 traffic, and that was all the dissector
 * was ever held to - by field name, never by value. A laptop on somebody
 * else's Wi-Fi overhears another vendor's mesh, so the frames here are built
 * from the reference's own layouts: every multicast message a Wi-Fi client
 * receives (topology discovery and notification, AP autoconfiguration search
 * and renew, push-button events), the topology TLVs, every TLV body the
 * dissector reads, a TLV and a message type nobody names, and a lone fragment.
 *
 * Left out of the comparison, each asserted below instead, are the rows where
 * the reference reads the bytes wrongly: IPv4 Type's addresses (it reads them
 * little-endian), both interface power TLVs (it never steps past their count),
 * and Push Button Join (it reads two MAC addresses two bytes long, which
 * throws). And an OUI's name: the reference resolves it from its own vendor
 * file, whose long names this build does not carry, so an OUI is its bytes.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';
import { pcapOf } from '../parity/synthetic';
import { arrive } from '../pipeline/arrival';
import type { Packet, ProtocolField } from '../../src/types/packet';

const MCAST = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x13];
const AL = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const IF = [0x02, 0x11, 0x22, 0x33, 0x44, 0x56];
const STA = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01];
const be16 = (n: number) => [n >> 8, n & 255];
const be32 = (n: number) => [n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255];
const ascii = (s: string, pad = 0) => { const b = [...new TextEncoder().encode(s)]; while (b.length < pad) b.push(0); return b; };
const tlv = (type: number, value: number[]) => [type, ...be16(value.length), ...value];
const al = tlv(0x01, AL);

let messageId = 0x100;
/** A CMDU from AL, multicast, padded to Ethernet's minimum as a mesh node sends it. */
function cmdu(type: number, tlvs: number[][], o: { relay?: boolean; fragment?: number; last?: boolean } = {}): Uint8Array {
  const flags = (o.last ?? true ? 0x80 : 0) | (o.relay ? 0x40 : 0);
  const f = [...MCAST, ...AL, 0x89, 0x3a, 0, 0, ...be16(type), ...be16(messageId++), o.fragment ?? 0, flags, ...tlvs.flat(), 0, 0, 0];
  while (f.length < 60) f.push(0);
  return Uint8Array.from(f);
}
const genericPhy = (variant: number, spec: number[]) => [0x00, 0x50, 0xf2, variant, spec.length, ...spec];

const cases: OracleCase[] = [
  // --- what a Wi-Fi client overhears -------------------------------------
  { label: 'a topology discovery', frame: cmdu(0x0000, [al, tlv(0x02, IF)]) },
  { label: 'a topology notification of a client joining', frame: cmdu(0x0001, [al, tlv(0x92, [...STA, ...IF, 0x80])], { relay: true }) },
  { label: '...and of one leaving', frame: cmdu(0x0001, [al, tlv(0x92, [...STA, ...IF, 0x00])], { relay: true }) },
  {
    label: 'an agent searching for its controller',
    frame: cmdu(0x0007, [al, tlv(0x0d, [0x00]), tlv(0x0e, [0x00]), tlv(0x80, [1, 0x01]), tlv(0x81, [1, 0x00]),
      tlv(0xb3, [0x03]), tlv(0xa9, [0x00, 0x00, 0x00])], { relay: true }),
  },
  {
    label: 'a search on 5 GHz with a DPP chirp',
    frame: cmdu(0x0007, [al, tlv(0x0d, [0x00]), tlv(0x0e, [0x01]), tlv(0x80, [2, 0x00, 0x01]), tlv(0x81, [1, 0x00]),
      tlv(0xb3, [0x02]), tlv(0xd3, [0xc0, ...STA, 4, 0xab, 0xcd, 0xef, 0x01])], { relay: true }),
  },
  { label: 'a search for roles and bands nobody names', frame: cmdu(0x0007, [al, tlv(0x0d, [0x05]), tlv(0x0e, [0x07])], { relay: true }) },
  { label: 'a controller renewing', frame: cmdu(0x000a, [al, tlv(0x0f, [0x00]), tlv(0x10, [0x03])], { relay: true }) },
  { label: 'a renew with reserved values', frame: cmdu(0x000a, [al, tlv(0x0f, [0x07]), tlv(0x10, [0x09])], { relay: true }) },
  {
    label: 'a push button press on two media',
    frame: cmdu(0x000b, [al, tlv(0x12, [2, ...be16(0x0001), 0, ...be16(0x0104), 10, ...IF, 0x00, 0x00, 0x24, 0x00])], { relay: true }),
  },
  {
    label: 'a push button press on a generic phy',
    frame: cmdu(0x000b, [al, tlv(0x12, [0]), tlv(0x19, [2, ...genericPhy(3, [1, 2]), ...genericPhy(0, [])])], { relay: true }),
  },
  { label: 'a controller announcing its capabilities', frame: cmdu(0x8044, [al, tlv(0xdd, [0xc0])]) },
  { label: 'a controller with no extra capabilities', frame: cmdu(0x8044, [al, tlv(0xdd, [0x00])]) },
  // --- topology ----------------------------------------------------------
  {
    label: 'device information, bridging, profile, identity and URL',
    frame: cmdu(0x0003, [al,
      tlv(0x03, [...AL, 2, ...IF, ...be16(0x0001), 0, ...STA, ...be16(0x0105), 10, ...IF, 0x00, 0x80, 0x24, 0x2a]),
      tlv(0x04, [2, 2, ...IF, ...STA, 1, ...IF]), tlv(0x1a, [0x01]),
      tlv(0x15, [...ascii('Living room', 64), ...ascii('Mesh Co', 64), ...ascii('X1', 64)]),
      tlv(0x16, ascii('http://192.168.68.1/')),
    ]),
  },
  {
    label: 'neighbours of both kinds',
    frame: cmdu(0x0003, [al, tlv(0x06, [...IF, ...STA, 0xaa, 0xbb, 0xcc, 0, 0, 2]), tlv(0x07, [...IF, ...AL, 0x80, ...STA, 0x00])]),
  },
  {
    label: 'IPv6 addresses',
    frame: cmdu(0x0003, [al, tlv(0x18, [1, ...IF,
      0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55, 2,
      1, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
      3, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, ...new Array(16).fill(0)])]),
  },
  {
    label: 'IPv4 addresses',
    frame: cmdu(0x0003, [al, tlv(0x17, [1, ...IF, 2, 1, 192, 168, 68, 20, 192, 168, 68, 1, 2, 10, 0, 0, 5, 0, 0, 0, 0])]),
  },
  {
    label: 'L2 neighbours and powered-off interfaces',
    frame: cmdu(0x0003, [al, tlv(0x1e, [1, ...IF, ...be16(2), ...STA, ...be16(1), ...AL, ...STA, ...be16(0)]),
      tlv(0x1b, [1, ...IF, ...be16(0x0104), ...genericPhy(1, [9])])]),
  },
  {
    label: 'a generic phy device',
    frame: cmdu(0x0003, [al, tlv(0x14, [...AL, 1, ...IF, 0x00, 0x50, 0xf2, 3, ...ascii('Home Plug', 32), 8, 2, ...ascii('http://x'), 0xaa, 0xbb])]),
  },
  // --- metrics, the bodies the dissector read before this test -------------
  {
    label: 'transmitter and receiver link metrics',
    frame: cmdu(0x0006, [al,
      tlv(0x09, [...AL, ...STA, ...IF, ...STA, ...be16(0x0105), 1, ...be32(3), ...be32(1000), ...be16(866), ...be16(100), ...be16(1200)]),
      tlv(0x0a, [...AL, ...STA, ...IF, ...STA, ...be16(0x0001), ...be32(0), ...be32(500), 0xc8]),
    ]),
  },
  { label: 'a vendor specific TLV', frame: cmdu(0x0004, [al, tlv(0x0b, [0x00, 0x1d, 0x0f, 1, 2, 3, 4])]) },
  {
    label: 'operational BSSes and their clients',
    frame: cmdu(0x0003, [al,
      tlv(0x83, [1, ...IF, 1, ...STA, 4, ...ascii('Home')]),
      tlv(0x84, [1, ...STA, ...be16(1), ...AL, ...be16(42)]),
    ]),
  },
  {
    label: 'AP and station metrics',
    frame: cmdu(0x800c, [al,
      tlv(0x94, [...IF, 30, ...be16(3), 0x80, 0x01, 0x02, 0x03]),
      tlv(0x96, [...STA, 1, ...IF, ...be32(10), ...be32(866000), ...be32(400000), 180]),
      tlv(0xa2, [...STA, ...be32(1), ...be32(2), ...be32(3), ...be32(4), ...be32(5), ...be32(6), ...be32(7)]),
      tlv(0xb0, [...STA, 1, 5, 9]),
    ]),
  },
  {
    label: 'radio and extended metrics',
    frame: cmdu(0x800c, [al,
      tlv(0xc6, [...IF, 160, 20, 30, 40]),
      tlv(0xc7, [...IF, ...be32(1), ...be32(2), ...be32(3), ...be32(4), ...be32(5), ...be32(6)]),
      tlv(0xc8, [...STA, 1, ...IF, ...be32(1), ...be32(2), ...be32(3), ...be32(4)]),
    ]),
  },
  // --- what nobody names ---------------------------------------------------
  { label: 'a TLV type nobody names', frame: cmdu(0x0003, [al, tlv(0x05, [1, 2, 3])]) },
  { label: 'a link metric query for every neighbour', frame: cmdu(0x0005, [al, tlv(0x08, [0x00, 0x02])]) },
  { label: '...and for one', frame: cmdu(0x0005, [al, tlv(0x08, [0x01, ...STA, 0x00])]) },
  { label: 'a message type nobody names', frame: cmdu(0x0013, [al]) },
  { label: 'an EasyMesh R6 message', frame: cmdu(0x8045, [al]) },
  { label: 'the first fragment of a split message', frame: cmdu(0x0003, [al, tlv(0x02, IF)], { last: false }) },
];

const packets = await compareWithReference(cases, {
  rows: /^ieee1905\.(?!(local_intf|vendor_specific)\.oui|ipv4_type\.(ipv4_addr|dhcp_server)|power_(chg|sts)\.)/,
});
await checkRevisit(cases);

// --- the rows left out, held here -----------------------------------------
function rows(packet: Packet | undefined, abbrev: string): unknown[] {
  const out: unknown[] = [];
  const walk = (fields: readonly ProtocolField[]) => {
    for (const f of fields) {
      if (f.abbrev === abbrev) out.push(f.value);
      if (f.children) walk(f.children);
    }
  };
  for (const layer of packet?.layers ?? []) walk(layer.fields);
  return out;
}
const byLabel = (label: string) => packets[cases.findIndex((c) => c.label === label)];

check('IPv4 Type reads its addresses in network byte order',
  JSON.stringify(rows(byLabel('IPv4 addresses'), 'ieee1905.ipv4_type.ipv4_addr')) === JSON.stringify(['192.168.68.20', '10.0.0.5']));
check('...and its DHCP servers',
  JSON.stringify(rows(byLabel('IPv4 addresses'), 'ieee1905.ipv4_type.dhcp_server')) === JSON.stringify(['192.168.68.1', '0.0.0.0']));
check('an interface OUI is drawn as one', rows(byLabel('a generic phy device'), 'ieee1905.local_intf.oui')[0] === '00:50:f2');
check('...and a vendor TLV\'s', rows(byLabel('a vendor specific TLV'), 'ieee1905.vendor_specific.oui')[0] === '00:1d:0f');

/** Frames the reference misreads, dissected through the same importer path. */
async function dissectOnly(frames: Uint8Array[]): Promise<Packet[]> {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-1905-'));
  try {
    const file = join(dir, 'extra.pcap');
    writeFileSync(file, pcapOf(frames));
    return (await arrive(file)).arrived.map((a) => a.packet);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const [pushJoin, change, status] = await dissectOnly([
  cmdu(0x000c, [al, tlv(0x13, [...AL, ...be16(0x1234), ...IF, ...STA])], { relay: true }),
  cmdu(0x000f, [al, tlv(0x1c, [2, ...IF, 0x01, ...STA, 0x02])]),
  cmdu(0x0010, [al, tlv(0x1d, [1, ...IF, 0x01])]),
]);
check('a push button join names the sender, its event and both interfaces',
  JSON.stringify(['ieee1905.sender.al_id', 'ieee1905.sender.msg_id', 'ieee1905.sender.joining_intf', 'ieee1905.new_device.intf'].map((a) => rows(pushJoin, a)[0]))
    === JSON.stringify(['02:11:22:33:44:55', '0x1234', '02:11:22:33:44:56', 'aa:bb:cc:00:00:01']));
check('a power change request reads each interface after the count',
  JSON.stringify([rows(change, 'ieee1905.power_chg.mac_addr'), rows(change, 'ieee1905.power_chg.state')])
    === JSON.stringify([['02:11:22:33:44:56', 'aa:bb:cc:00:00:01'], ['1, PWR_ON', '2, PWR_SAVE']]));
check('...and so does a power change status',
  JSON.stringify([rows(status, 'ieee1905.power_sts.mac_addr'), rows(status, 'ieee1905.power_sts.state')])
    === JSON.stringify([['02:11:22:33:44:56'], ['1, No change made']]));
check('a client joining is the frame\'s first finding, by name',
  rows(byLabel('a topology notification of a client joining'), 'ieee1905.assoc_event.assoc_event')[0] === 'Client has joined the BSS');
finish('IEEE 1905.1a');
