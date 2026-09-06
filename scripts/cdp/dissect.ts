/**
 * CDP, against tshark.
 *
 *   npx tsx scripts/cdp/dissect.ts
 *
 * The only protocol in this batch that is not on UDP: it rides an 802.3 frame
 * with an LLC/SNAP header, which means the dispatch is as much under test as
 * the decoding. **A SNAP protocol id is only unique within its OUI**, so
 * 0x2000 under Cisco's 00:00:0C is CDP and 0x2000 under anybody else's is
 * something nobody has assigned. The pair below asserts both halves; a test
 * that only sent Cisco frames would pass with the OUI ignored.
 *
 * Two decoding traps, both in the TLV walk. A TLV's length **includes its own
 * four-byte header**, so a length of 0 read as "advance by 0" is an infinite
 * loop on hostile input, and a length of 4 is an empty value rather than a
 * malformed one. And the Info line is assembled from two TLVs that may each be
 * absent, separated by *two* spaces.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { dissectCdp, CDP_SNAP_PID, CISCO_OUI } from '../../src/services/dissectors/cdp';
import {
  Bytes, check, failureCount, internetChecksum, llcSnapFrame, runCases, type SyntheticCase,
} from '../parity/synthetic';

const DEVICE_ID = 1, ADDRESSES = 2, PORT_ID = 3, CAPABILITIES = 4,
  SOFTWARE_VERSION = 5, PLATFORM = 6, NATIVE_VLAN = 10, DUPLEX = 11;

/** One TLV; the declared length counts these four header bytes. */
function tlv(type: number, value: ArrayLike<number>): number[] {
  const bytes = Array.from(value);
  return [(type >> 8) & 0xff, type & 0xff,
    ((bytes.length + 4) >> 8) & 0xff, (bytes.length + 4) & 0xff, ...bytes];
}

const ascii = (text: string) => [...text].map((c) => c.charCodeAt(0));

/** A CDP message with its checksum filled in. */
function cdp(...tlvs: number[][]): Uint8Array {
  const bytes = new Bytes().u8(2, 180).u16(0).u8(...tlvs.flat()).build();
  const sum = internetChecksum(bytes);
  bytes[2] = (sum >> 8) & 0xff;
  bytes[3] = sum & 0xff;
  return bytes;
}

const full = cdp(
  tlv(DEVICE_ID, ascii('switch.example.com')),
  tlv(PORT_ID, ascii('GigabitEthernet0/1')),
  tlv(CAPABILITIES, [0, 0, 0, 0x28]),           // Switch | IGMP capable
  tlv(SOFTWARE_VERSION, ascii('Cisco IOS Software, Version 15.2')),
  tlv(PLATFORM, ascii('cisco WS-C2960-24TT-L')),
  tlv(NATIVE_VLAN, [0, 100]),
  tlv(DUPLEX, [1]),
);

const cisco = (payload: Uint8Array) => llcSnapFrame(CISCO_OUI, CDP_SNAP_PID, payload);

const cases: SyntheticCase[] = [
  { name: 'a full advertisement', frame: cisco(full) },
  { name: 'a device id and port alone',
    frame: cisco(cdp(tlv(DEVICE_ID, ascii('core-sw-1')), tlv(PORT_ID, ascii('Fa0/24')))) },
  // Each half of the Info line can be absent on its own.
  { name: 'a device id with no port', frame: cisco(cdp(tlv(DEVICE_ID, ascii('ap-lobby')))) },
  { name: 'a port with no device id', frame: cisco(cdp(tlv(PORT_ID, ascii('Fa0/1')))) },
  { name: 'a router rather than a switch',
    frame: cisco(cdp(tlv(DEVICE_ID, ascii('rtr-edge')), tlv(PORT_ID, ascii('Gi0/0')),
      tlv(CAPABILITIES, [0, 0, 0, 0x01]))) },
  { name: 'an advertisement carrying an address',
    frame: cisco(cdp(tlv(DEVICE_ID, ascii('mgmt-sw')), tlv(PORT_ID, ascii('Gi1/0/1')),
      tlv(ADDRESSES, [0, 0, 0, 1, 1, 1, 0xcc, 0, 2, 0x81, 0, 0, 0, 4, 192, 0, 2, 10]))) },
  // A serial number where a hostname would be, which is what an unconfigured
  // switch advertises - and the reason this is not folded into name resolution.
  { name: 'a device id that is a serial number',
    frame: cisco(cdp(tlv(DEVICE_ID, ascii('FDO1234X5YZ')), tlv(PORT_ID, ascii('Gi0/1')))) },
];

async function main(): Promise<void> {
  await runCases(cases);

  // --- the OUI is what gives the protocol id meaning --------------------------------
  //
  // Dispatching on 0x2000 alone would claim a SNAP frame under any
  // organisation code. `dissectCdp` itself cannot see the OUI, so this is
  // checked through the whole frame.
  const wrongOui = llcSnapFrame(0x00000e, CDP_SNAP_PID, full);
  const other = decodeRawEthernetPacket(
    wrongOui, 1, 1_700_000_000_000_000, 0, 0, wrongOui.length).packet;
  check('0x2000 under another OUI is not CDP',
    (other.frameProtocols ?? []).includes('cdp'), false);
  const right = decodeRawEthernetPacket(
    cisco(full), 2, 1_700_000_000_000_000, 0, 1, cisco(full).length).packet;
  check('...and under Cisco\'s it is', (right.frameProtocols ?? []).includes('cdp'), true);

  // --- the TLV walk terminates ---------------------------------------------------------
  //
  // A length under the four-byte header cannot be advanced past. Read as
  // "advance by the length" this spins forever on a frame anybody can send.
  const zeroLength = cdp(tlv(DEVICE_ID, ascii('sw')));
  zeroLength[6] = 0; zeroLength[7] = 0;
  const walked = dissectCdp(zeroLength, 0, zeroLength.length);
  check('a zero-length TLV ends the walk rather than spinning', walked !== null, true);
  check('...and nothing is read past it', walked?.fields['cdp.deviceid'], undefined);

  const pastEnd = cdp(tlv(DEVICE_ID, ascii('sw')));
  pastEnd[6] = 0xff; pastEnd[7] = 0xff;
  check('a TLV length past the frame ends the walk',
    dissectCdp(pastEnd, 0, pastEnd.length)?.fields['cdp.deviceid'], undefined);

  // A length of exactly 4 is an empty value, not a malformed TLV.
  const emptyValue = cdp(tlv(DEVICE_ID, []), tlv(PORT_ID, ascii('Gi0/1')));
  check('an empty TLV is read and the walk continues',
    dissectCdp(emptyValue, 0, emptyValue.length)?.fields['cdp.portid'], 'Gi0/1');

  // --- what is not CDP -------------------------------------------------------------------
  const version9 = cdp(tlv(DEVICE_ID, ascii('sw')));
  version9[0] = 9;
  check('a version nobody defines is declined', dissectCdp(version9, 0, version9.length), null);
  check('three bytes are not a header', dissectCdp(full, 0, 3), null);

  // --- the fields ---------------------------------------------------------------------------
  const read = dissectCdp(full, 0, full.length);
  check('the device id is published', read?.fields['cdp.deviceid'], 'switch.example.com');
  check('the port id is published', read?.fields['cdp.portid'], 'GigabitEthernet0/1');
  check('the native VLAN is published', read?.fields['cdp.native_vlan'], 100);
  check('the duplex is published', read?.fields['cdp.duplex'], 'Full');
  check('the platform is published', read?.fields['cdp.platform'], 'cisco WS-C2960-24TT-L');
  // The capability bits say what the neighbour IS, and read as a bare number
  // unless they are named.
  const capabilities = read?.layer.fields.find((f) => f.name === 'Capabilities');
  check('the capabilities are named', capabilities?.value, 'Switch, IGMP capable');

  // --- what reaches the rest of the app -------------------------------------------------------
  check('the protocol chain runs through LLC', right.frameProtocols,
    ['frame', 'eth', 'llc', 'cdp']);

  console.log();
  if (failureCount() > 0) {
    console.log(`${failureCount()} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All CDP checks passed.');
  process.exit(0);
}

main();
