/**
 * BFD, against tshark.
 *
 *   npx tsx scripts/bfd/dissect.ts
 *
 * A fixed header with no options and no state, so the decoding is barely worth
 * asserting. What is worth asserting is the **diagnostic**, because that is
 * the field a reader actually comes to BFD for: it names why the session went
 * down, and the codes are close enough in meaning that an off-by-one in the
 * table is invisible unless each is checked.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { dissectBfd } from '../../src/services/dissectors/bfd';
import {
  Bytes, check, failureCount, runCases, udpFrame, type SyntheticCase,
} from '../parity/synthetic';

/** A control packet: version 1, then the fixed 24-byte body. */
function control(diagnostic: number, state: number, flags = 0): Uint8Array {
  return new Bytes()
    .u8((1 << 5) | diagnostic, (state << 6) | flags, 3, 24)
    .u32(0x00000001).u32(0x00000002)
    .u32(1_000_000).u32(1_000_000).u32(0)
    .build();
}

const cases: SyntheticCase[] = [
  { name: 'a session that is Up', frame: udpFrame(49152, 3784, control(0, 3)) },
  { name: 'a session coming up', frame: udpFrame(49152, 3784, control(0, 2)) },
  { name: 'a detection timeout', frame: udpFrame(49152, 3784, control(1, 1)) },
  { name: 'a neighbour that signalled down', frame: udpFrame(49152, 3784, control(3, 1)) },
  { name: 'an administrative shutdown', frame: udpFrame(49152, 3784, control(7, 0)) },
  { name: 'a path down', frame: udpFrame(49152, 3784, control(5, 1)) },
  // The Poll/Final exchange, which is how a timer change is agreed.
  { name: 'a poll', frame: udpFrame(49152, 3784, control(0, 3, 0x20)) },
  { name: 'a final', frame: udpFrame(49152, 3784, control(0, 3, 0x10)) },
  { name: 'demand mode', frame: udpFrame(49152, 3784, control(0, 3, 0x02)) },
  // Multihop carries the same control header.
  { name: 'a control packet on the multihop port', frame: udpFrame(49152, 4784, control(0, 3)) },
  // Port 3785 does NOT. An echo packet's content is the sender's own business
  // (RFC 5880 §5), and reading it with the control rules would print a
  // diagnostic and a session state out of an opaque payload.
  { name: 'an echo packet, which has no format',
    frame: udpFrame(49152, 3785, new Bytes().raw(new Array(24).fill(0x5a)).build()) },
];

async function main(): Promise<void> {
  await runCases(cases);

  // --- every diagnostic is distinct ------------------------------------------------
  //
  // Eight codes whose names are all plausible for each other. Checked one at a
  // time, because a table shifted by one still reads as sensible English.
  const EXPECTED: [number, string][] = [
    [0, 'No Diagnostic'],
    [1, 'Control Detection Time Expired'],
    [2, 'Echo Function Failed'],
    [3, 'Neighbor Signaled Session Down'],
    [4, 'Forwarding Plane Reset'],
    [5, 'Path Down'],
    [6, 'Concatenated Path Down'],
    [7, 'Administratively Down'],
    [8, 'Reverse Concatenated Path Down'],
  ];
  for (const [code, name] of EXPECTED) {
    const bytes = control(code, 3);
    check(`diagnostic ${code} is ${name}`,
      dissectBfd(bytes, 0, bytes.length)?.info, `Diag: ${name}, State: Up, Flags: 0x00`);
  }

  // --- what is not BFD ---------------------------------------------------------------
  const version0 = control(0, 3);
  version0[0] = 0x00;
  check('version 0 is declined', dissectBfd(version0, 0, version0.length), null);
  const version2 = control(0, 3);
  version2[0] = 0x40;
  check('...and so is version 2', dissectBfd(version2, 0, version2.length), null);

  // The header declares its own size, which is the check that makes this safe
  // to read on a port somebody reassigned.
  const shortLength = control(0, 3);
  shortLength[3] = 12;
  check('a declared length under the header size is declined',
    dissectBfd(shortLength, 0, shortLength.length), null);
  const longLength = control(0, 3);
  longLength[3] = 200;
  check('...and one past the datagram', dissectBfd(longLength, 0, longLength.length), null);
  const truncated = control(0, 3).subarray(0, 20);
  check('a truncated packet is declined', dissectBfd(truncated, 0, truncated.length), null);

  // --- what reaches the rest of the app ------------------------------------------------
  const frame = udpFrame(49152, 3784, control(1, 1));
  const { packet } = decodeRawEthernetPacket(frame, 1, 1_700_000_000_000_000, 0, 0, frame.length);
  check('the protocol chain is right', packet.frameProtocols, ['frame', 'eth', 'ip', 'udp', 'bfd']);
  check('the diagnostic is published', packet.fields?.['bfd.diag'], 1);
  check('the state is published', packet.fields?.['bfd.sta'], 1);
  check('the discriminators are published', packet.fields?.['bfd.my_discriminator'], 1);
  check('...both of them', packet.fields?.['bfd.your_discriminator'], 2);

  console.log();
  if (failureCount() > 0) {
    console.log(`${failureCount()} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All BFD checks passed.');
  process.exit(0);
}

main();
