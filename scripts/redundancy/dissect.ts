/**
 * VRRP and HSRP - the two first-hop redundancy protocols - against tshark.
 *
 *   npx tsx scripts/redundancy/dissect.ts
 *
 * One script for both because they answer the same question and the
 * interesting properties are shared: which router holds the virtual address,
 * and what happened when it stopped.
 *
 * Two rules here were established by probing rather than by reading, and both
 * are the kind that a spec-derived implementation gets wrong:
 *
 *   - **HSRP is only HSRP when it is addressed to its group.** A byte-identical
 *     datagram on port 1985 to a unicast address comes back from tshark as
 *     plain `UDP`. The case below asserts both halves, because a dissector
 *     that ignored the address would pass a test that only sent multicast.
 *   - **VRRP v2 and v3 disagree about the unit of their advertisement
 *     interval** - seconds against centiseconds - so a single rule reports one
 *     of them a hundred times out. The two versions are checked separately.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { dissectHsrp, HSRP_V1_GROUP } from '../../src/services/dissectors/hsrp';
import { dissectVrrp } from '../../src/services/dissectors/vrrp';
import {
  Bytes, check, failureCount, internetChecksum, ipFrame, runCases, udpFrameTo,
  type SyntheticCase,
} from '../parity/synthetic';

// --- HSRP ---------------------------------------------------------------------

function hsrp(opcode: number, state: number, priority = 100, group = 1): Uint8Array {
  return new Bytes()
    .u8(0, opcode, state, 3, 10, priority, group, 0)
    .ascii('cisco').zeros(3)
    .ipv4('192.0.2.10')
    .build();
}

const toGroup = (payload: Uint8Array) =>
  udpFrameTo('192.0.2.1', HSRP_V1_GROUP, 1985, 1985, payload);

// --- VRRP ---------------------------------------------------------------------

/** A v2 advertisement, with the checksum the dissector's caller will verify. */
function vrrpV2(vrid: number, priority: number, addresses: string[] = ['192.0.2.10']): Uint8Array {
  const b = new Bytes()
    .u8(0x21, vrid, priority, addresses.length, 0, 1).u16(0);
  for (const address of addresses) b.ipv4(address);
  const bytes = b.zeros(8).build();
  const sum = internetChecksum(bytes);
  bytes[6] = (sum >> 8) & 0xff;
  bytes[7] = sum & 0xff;
  return bytes;
}

/** A v3 advertisement: no authentication, and a 12-bit centisecond interval. */
function vrrpV3(vrid: number, priority: number, maxAdverInt: number): Uint8Array {
  return new Bytes()
    .u8(0x31, vrid, priority, 1)
    .u16(maxAdverInt & 0x0fff).u16(0)
    .ipv4('192.0.2.10')
    .build();
}

const cases: SyntheticCase[] = [
  // --- HSRP ---
  { name: 'an HSRP hello from the active router', frame: toGroup(hsrp(0, 16)) },
  { name: 'an HSRP hello from the standby', frame: toGroup(hsrp(0, 8)) },
  { name: 'an HSRP router listening', frame: toGroup(hsrp(0, 2)) },
  { name: 'an HSRP router speaking', frame: toGroup(hsrp(0, 4)) },
  // The two messages that explain an outage.
  { name: 'an HSRP coup', frame: toGroup(hsrp(1, 8)) },
  { name: 'an HSRP resign', frame: toGroup(hsrp(2, 16)) },
  { name: 'an HSRP hello in the initial state', frame: toGroup(hsrp(0, 0)) },
  // Addressed to a host rather than to the group. tshark declines it, so this
  // must too - the port is unregistered enough that something else will use it.
  { name: 'a datagram on port 1985 to a host, which is not HSRP',
    frame: udpFrameTo('192.0.2.1', '192.0.2.2', 1985, 1985, hsrp(0, 16)),
    expectProtocol: 'UDP', expectInfo: '1985 → 1985 Len=20' },

  // --- VRRP ---
  { name: 'a VRRPv2 advertisement', frame: ipFrame(112, vrrpV2(1, 100)) },
  { name: 'a VRRPv2 from the address owner', frame: ipFrame(112, vrrpV2(1, 255)) },
  // Priority zero is a router giving the address up - the packet that explains
  // a failover, and the one worth finding in a capture.
  { name: 'a VRRPv2 resignation', frame: ipFrame(112, vrrpV2(1, 0)) },
  { name: 'a VRRPv2 carrying two addresses',
    frame: ipFrame(112, vrrpV2(7, 120, ['192.0.2.10', '192.0.2.11'])) },
  { name: 'a VRRPv3 advertisement', frame: ipFrame(112, vrrpV3(1, 100, 100)) },
  { name: 'a VRRPv3 with a sub-second interval', frame: ipFrame(112, vrrpV3(1, 100, 25)) },
];

async function main(): Promise<void> {
  await runCases(cases);

  // --- HSRP: the states are distinct ---------------------------------------------
  //
  // The state values are not consecutive - 0, 1, 2, 4, 8, 16 - so a table
  // written as an array indexes the wrong name for every state above Listen.
  const STATES: [number, string][] = [
    [0, 'Initial'], [1, 'Learn'], [2, 'Listen'], [4, 'Speak'], [8, 'Standby'], [16, 'Active'],
  ];
  for (const [value, name] of STATES) {
    const bytes = hsrp(0, value);
    check(`HSRP state ${value} is ${name}`,
      dissectHsrp(bytes, 0, bytes.length)?.info, `Hello (state ${name})`);
  }
  const badState = hsrp(0, 3);
  check('a state nobody defines is declined', dissectHsrp(badState, 0, badState.length), null);
  const v2 = hsrp(0, 16);
  v2[0] = 2;
  check('HSRPv2 is declined rather than read with v1 rules',
    dissectHsrp(v2, 0, v2.length), null);

  // --- VRRP: the interval means different things in the two versions -------------
  const v2Advert = vrrpV2(1, 100);
  const readV2 = dissectVrrp(v2Advert, 0, v2Advert.length);
  check('v2 reports its interval in seconds', readV2?.fields['vrrp.adver_int'], 1);
  check('...and has an auth type', readV2?.fields['vrrp.auth_type'], 0);
  const v3Advert = vrrpV3(1, 100, 100);
  const readV3 = dissectVrrp(v3Advert, 0, v3Advert.length);
  check('v3 reports its interval in centiseconds', readV3?.fields['vrrp.short_adver_int'], 100);
  check('...and has no auth type at all', readV3?.fields['vrrp.auth_type'], undefined);

  // --- VRRP: what is not VRRP -------------------------------------------------------
  const version1 = vrrpV2(1, 100);
  version1[0] = 0x11;
  check('VRRPv1 is declined', dissectVrrp(version1, 0, version1.length), null);
  const badType = vrrpV2(1, 100);
  badType[0] = 0x22;
  check('a type other than Advertisement is declined',
    dissectVrrp(badType, 0, badType.length), null);
  // The address count has to describe the packet, which is the only length
  // check the format offers.
  const tooManyAddresses = vrrpV2(1, 100);
  tooManyAddresses[3] = 40;
  check('an address count past the packet is declined',
    dissectVrrp(tooManyAddresses, 0, tooManyAddresses.length), null);

  // --- what reaches the rest of the app ------------------------------------------------
  const hsrpFrame = toGroup(hsrp(2, 16));
  const hsrpPacket = decodeRawEthernetPacket(
    hsrpFrame, 1, 1_700_000_000_000_000, 0, 0, hsrpFrame.length).packet;
  check('the HSRP protocol chain is right', hsrpPacket.frameProtocols,
    ['frame', 'eth', 'ip', 'udp', 'hsrp']);
  check('the opcode is published', hsrpPacket.fields?.['hsrp.opcode'], 2);
  check('the virtual address is published', hsrpPacket.fields?.['hsrp.virt_ip'], '192.0.2.10');

  const vrrpFrame = ipFrame(112, vrrpV2(7, 0));
  const vrrpPacket = decodeRawEthernetPacket(
    vrrpFrame, 2, 1_700_000_000_000_000, 0, 1, vrrpFrame.length).packet;
  check('the VRRP protocol chain is right', vrrpPacket.frameProtocols,
    ['frame', 'eth', 'ip', 'vrrp']);
  check('the router id is published', vrrpPacket.fields?.['vrrp.virt_rtr_id'], 7);
  check('a resignation publishes priority zero', vrrpPacket.fields?.['vrrp.prio'], 0);

  console.log();
  if (failureCount() > 0) {
    console.log(`${failureCount()} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All redundancy-protocol checks passed.');
  process.exit(0);
}

main();
