/**
 * LLDP's Info column, against tshark.
 *
 *   npx tsx scripts/lldp/dissect.ts
 *
 * One thing under test, and it is the one the fixtures cannot settle: the Info
 * line **ends in a space**. Each element is followed by the separator rather
 * than joined by it, so `join(' ')` is one character short on every LLDP frame
 * in every capture.
 *
 * The two fixtures contain exactly one LLDP frame between them, which is
 * enough to notice the trailing space and not enough to know whether it
 * survives a System Name or a System Description being present. Synthetic
 * frames at each combination settle it, which is what this file is - the same
 * argument `scripts/parity/synthetic.ts` was built for.
 *
 * It is the third dissector here to trip on trailing whitespace, after SIP's
 * `" | "` and CDP's two spaces. A `trimEnd()` anywhere in the chain would
 * silently undo all three.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import {
  Bytes, check, failureCount, runCases, type SyntheticCase,
} from '../parity/synthetic';

/** An LLDP TLV: 7 bits of type, 9 of length, then the value. */
function tlv(type: number, value: readonly number[]): number[] {
  return [(type << 1) | ((value.length >> 8) & 1), value.length & 0xff, ...value];
}

const ascii = (text: string) => [...text].map((c) => c.charCodeAt(0));
const MAC = [0x04, 0x7c, 0x16, 0x52, 0xdb, 0x17];

/** An LLDP frame carrying these TLVs, terminated by the mandatory End TLV. */
function lldpFrame(...tlvs: number[][]): Uint8Array {
  return new Bytes()
    .mac('01:80:c2:00:00:0e').mac('04:7c:16:52:db:17').u16(0x88cc)
    .u8(...tlvs.flat())
    .u8(...tlv(0, []))
    .build();
}

// Chassis subtype 7 is "locally assigned", which tshark renders `LA/`; port
// subtype 3 is a MAC address, rendered `MA/`.
const chassis = tlv(1, [7, ...ascii('ROTEM')]);
const port = tlv(2, [3, ...MAC]);
const ttl = tlv(3, [0x0e, 0x11]);              // 3601 seconds
const systemName = tlv(5, ascii('switch-1'));
const systemDescription = tlv(6, ascii('Test Switch'));

const cases: SyntheticCase[] = [
  { name: 'the three mandatory TLVs', frame: lldpFrame(chassis, port, ttl) },
  { name: '...with a System Name', frame: lldpFrame(chassis, port, ttl, systemName) },
  { name: '...and a System Description',
    frame: lldpFrame(chassis, port, ttl, systemName, systemDescription) },
  // A short TTL, so the number is read rather than matching by luck.
  { name: 'a one-second TTL', frame: lldpFrame(chassis, port, tlv(3, [0x00, 0x01])) },
  // An interface-name port id, which renders with a different prefix.
  { name: 'an interface-name port id',
    frame: lldpFrame(chassis, tlv(2, [5, ...ascii('Gi0/1')]), ttl) },
];

async function main(): Promise<void> {
  await runCases(cases);

  // Stated separately from the column comparison above, because a check
  // written as "contains the right elements" would pass without it and that is
  // exactly how the character went missing.
  const frame = lldpFrame(chassis, port, ttl);
  const { packet } = decodeRawEthernetPacket(frame, 1, 1_700_000_000_000_000, 0, 0, frame.length);
  check('the Info line ends in a space', packet.info.endsWith(' '), true);
  check('...and is otherwise what the reference analyzer writes',
    packet.info, 'LA/ROTEM MA/04:7c:16:52:db:17 3601 ');

  const withName = lldpFrame(chassis, port, ttl, systemName);
  const named = decodeRawEthernetPacket(
    withName, 2, 1_700_000_000_000_000, 0, 1, withName.length).packet;
  check('a System Name does not consume the trailing space',
    named.info.endsWith(' '), true);

  check('the protocol chain is right', packet.frameProtocols, ['frame', 'eth', 'lldp']);

  console.log();
  if (failureCount() > 0) {
    console.log(`${failureCount()} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All LLDP checks passed.');
  process.exit(0);
}

main();
