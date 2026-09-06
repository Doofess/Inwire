/**
 * NBDS - the NetBIOS Datagram Service - against tshark.
 *
 *   npx tsx scripts/nbds/dissect.ts
 *
 * The third NetBIOS service, and the one that reuses the least from the other
 * two: it shares only RFC 1001 §14.1 first-level name encoding with NBNS, and
 * has its own header, its own message types and **two** encoded names per
 * datagram where a name query has one question.
 *
 * The property worth pinning is that both names are decoded. A datagram whose
 * source name is read and whose destination name is not still looks right -
 * the Info column names neither - which is exactly the bug a test that only
 * checks the message type would miss.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { dissectNbds } from '../../src/services/dissectors/nbds';
import {
  Bytes, check, failureCount, runCases, udpFrame, type SyntheticCase,
} from '../parity/synthetic';

/** RFC 1001 §14.1: each byte becomes two nibbles offset from 'A'. */
function encodedName(name: string, suffix: number): number[] {
  const raw = [...name.toUpperCase().padEnd(15, ' ')].map((c) => c.charCodeAt(0)).concat(suffix);
  const out: number[] = [32];
  for (const b of raw) out.push(0x41 + (b >> 4), 0x41 + (b & 0x0f));
  out.push(0);
  return out;
}

function datagram(type: number, userData: Uint8Array, source = 'WORKSTATION', dest = 'WORKGROUP',
  destSuffix = 0x1e): Uint8Array {
  const names = new Bytes()
    .u8(...encodedName(source, 0x00))
    .u8(...encodedName(dest, destSuffix))
    .build();
  const body = new Bytes().raw(names).raw(userData).build();
  return new Bytes()
    .u8(type, 0x0a).u16(0x1234)
    .ipv4('192.0.2.1').u16(138)
    .u16(body.length).u16(0)
    .raw(body)
    .build();
}

const mailslot = new Bytes().ascii('\\MAILSLOT\\BROWSE').u8(0).raw(new Array(24).fill(0x00)).build();

const cases: SyntheticCase[] = [
  { name: 'a direct group datagram', frame: udpFrame(138, 138, datagram(0x11, mailslot)) },
  { name: 'a direct unique datagram', frame: udpFrame(138, 138, datagram(0x10, mailslot)) },
  { name: 'a broadcast datagram', frame: udpFrame(138, 138, datagram(0x12, mailslot)) },
  // A name at the full fifteen characters, which is where the padding rule and
  // the suffix byte meet.
  { name: 'a datagram from a fifteen-character name',
    frame: udpFrame(138, 138, datagram(0x11, mailslot, 'ABCDEFGHIJKLMNO')) },
  // The messenger service suffix, which is a different name for the same host.
  { name: 'a datagram to a messenger name',
    frame: udpFrame(138, 138, datagram(0x11, mailslot, 'WORKSTATION', 'ADMINISTRATOR', 0x03)) },
];

async function main(): Promise<void> {
  await runCases(cases);

  // --- both names, not just the first --------------------------------------------
  const packetBytes = datagram(0x11, mailslot, 'ALICE-PC', 'ACCOUNTS', 0x1e);
  const read = dissectNbds(packetBytes, 0, packetBytes.length);
  check('the source name is decoded', read?.fields['nbdgm.source_name'], 'ALICE-PC<00>');
  check('...and so is the destination', read?.fields['nbdgm.destination_name'], 'ACCOUNTS<1E>');
  check('the source endpoint is read', read?.fields['nbdgm.src.ip'], '192.0.2.1');
  check('...with its port', read?.fields['nbdgm.src.port'], 138);

  // --- what is not NetBIOS ---------------------------------------------------------
  const badType = datagram(0x11, mailslot);
  badType[0] = 0x20;
  check('an unknown message type is declined', dissectNbds(badType, 0, badType.length), null);

  // A datagram whose names are not RFC 1001 encoded is not NetBIOS, however
  // well the header reads - that is what keeps this off other UDP traffic.
  const badName = datagram(0x11, mailslot);
  badName[15] = 0x7a;   // a lower-case letter cannot appear in an encoded name
  check('a name that is not first-level encoded is declined',
    dissectNbds(badName, 0, badName.length), null);

  const truncated = packetBytes.subarray(0, 40);
  check('a datagram cut off inside its names is declined',
    dissectNbds(truncated, 0, truncated.length), null);
  check('a header alone is declined', dissectNbds(packetBytes, 0, 9), null);

  // --- what reaches the rest of the app ---------------------------------------------
  const frame = udpFrame(138, 138, packetBytes);
  const { packet } = decodeRawEthernetPacket(frame, 1, 1_700_000_000_000_000, 0, 0, frame.length);
  check('the protocol chain is right', packet.frameProtocols,
    ['frame', 'eth', 'ip', 'udp', 'nbdgm']);
  check('the message type is published', packet.fields?.['nbdgm.type'], 0x11);
  const layer = packet.layers.find((l) => l.name === 'NetBIOS Datagram Service');
  check('the tree carries an NBDS layer', layer !== undefined, true);
  // The user data is an SMB Mailslot and is deliberately not decoded, but its
  // size is reported rather than silently dropped.
  check('the mailslot is reported as bytes, not read',
    layer?.fields.some((f) => f.name === 'User data'), true);

  console.log();
  if (failureCount() > 0) {
    console.log(`${failureCount()} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All NBDS checks passed.');
  process.exit(0);
}

main();
