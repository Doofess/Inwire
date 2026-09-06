/**
 * TFTP, against tshark.
 *
 *   npx tsx scripts/tftp/dissect.ts
 *
 * Every field in TFTP is NUL-terminated and nothing declares a length, so the
 * cases that matter are the ones where a string runs off the end of the
 * datagram. A parser that reads a missing terminator as "the rest of the
 * buffer" produces a plausible filename out of whatever followed, which is the
 * failure this pins.
 *
 * The error case is the one worth reading twice: the Info line names the error
 * **code** and then prints the server's own message, and the two are usually
 * the same words - so a test whose message happens to match its code cannot
 * tell the two apart. There is a case below where they differ.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { dissectTftp } from '../../src/services/dissectors/tftp';
import {
  Bytes, check, failureCount, runCases, udpFrame, type SyntheticCase,
} from '../parity/synthetic';

const rrq = new Bytes().u16(1).ascii('boot.bin').u8(0).ascii('octet').u8(0).build();
const wrq = new Bytes().u16(2).ascii('config.txt').u8(0).ascii('netascii').u8(0).build();
const data = new Bytes().u16(3).u16(1).raw(new Array(512).fill(0x41)).build();
const ack = new Bytes().u16(4).u16(1).build();
const oack = new Bytes().u16(6).ascii('blksize').u8(0).ascii('1428').u8(0).build();

const errorOf = (code: number, message: string) =>
  new Bytes().u16(5).u16(code).ascii(message).u8(0).build();

const cases: SyntheticCase[] = [
  { name: 'a read request', frame: udpFrame(50000, 69, rrq) },
  { name: 'a write request', frame: udpFrame(50000, 69, wrq) },
  { name: 'a full data block', frame: udpFrame(50000, 69, data) },
  { name: 'an acknowledgement', frame: udpFrame(50000, 69, ack) },
  { name: 'an option acknowledgement', frame: udpFrame(50000, 69, oack) },
  { name: 'a File not found error', frame: udpFrame(50000, 69, errorOf(1, 'File not found')) },
  // The code's name and the server's message are separate strings. A server
  // that sends its own wording is what proves they are read separately.
  { name: 'an error whose message is not its code name',
    frame: udpFrame(50000, 69, errorOf(2, 'no read permission on /tftpboot')) },
  { name: 'an option negotiation failure', frame: udpFrame(50000, 69, errorOf(8, 'blksize')) },
  // A final short block, which is how a transfer ends.
  { name: 'a short final data block',
    frame: udpFrame(50000, 69, new Bytes().u16(3).u16(7).ascii('tail').build()) },
  // A request carrying RFC 2347 options after the mode.
  { name: 'a read request with options', frame: udpFrame(50000, 69, new Bytes()
      .u16(1).ascii('vmlinuz').u8(0).ascii('octet').u8(0)
      .ascii('blksize').u8(0).ascii('1428').u8(0)
      .ascii('tsize').u8(0).ascii('0').u8(0).build()) },
];

async function main(): Promise<void> {
  await runCases(cases);

  // --- strings that do not terminate ------------------------------------------
  //
  // Nothing in TFTP declares a length, so an unterminated string is the whole
  // of the format's attack surface. Each of these must be declined rather than
  // read to the end of the datagram.
  const noModeTerminator = new Bytes().u16(1).ascii('boot.bin').u8(0).ascii('octet').build();
  check('a request whose mode has no terminator is declined',
    dissectTftp(noModeTerminator, 0, noModeTerminator.length), null);
  const noFileTerminator = new Bytes().u16(1).ascii('boot.bin').build();
  check('...nor one whose filename has none',
    dissectTftp(noFileTerminator, 0, noFileTerminator.length), null);
  const errNoMessage = new Bytes().u16(5).u16(1).ascii('truncated').build();
  check('...nor an error whose message has none',
    dissectTftp(errNoMessage, 0, errNoMessage.length), null);

  // --- opcodes ------------------------------------------------------------------
  const opcode0 = new Bytes().u16(0).u16(1).build();
  check('opcode 0 is not TFTP', dissectTftp(opcode0, 0, opcode0.length), null);
  const opcode7 = new Bytes().u16(7).u16(1).build();
  check('nor is opcode 7', dissectTftp(opcode7, 0, opcode7.length), null);
  check('a two-byte datagram carries no opcode body',
    dissectTftp(new Bytes().u16(4).build(), 0, 2), null);

  // An OACK with no options at all is not one - the options are its entire
  // content, and an empty one would print a bare "Option Acknowledgement, ".
  const emptyOack = new Bytes().u16(6).build();
  check('an option acknowledgement with no options is declined',
    dissectTftp(emptyOack, 0, emptyOack.length), null);

  // --- what reaches the rest of the app ------------------------------------------
  const frame = udpFrame(50000, 69, rrq);
  const { packet } = decodeRawEthernetPacket(frame, 1, 1_700_000_000_000_000, 0, 0, frame.length);
  check('the protocol chain is right', packet.frameProtocols, ['frame', 'eth', 'ip', 'udp', 'tftp']);
  check('the filename is published', packet.fields?.['tftp.source_file'], 'boot.bin');
  check('the transfer mode is published', packet.fields?.['tftp.type'], 'octet');
  check('the opcode is published', packet.fields?.['tftp.opcode'], 1);

  const blockFrame = udpFrame(50000, 69, data);
  const block = decodeRawEthernetPacket(blockFrame, 2, 1_700_000_000_000_000, 0, 1, blockFrame.length);
  check('a data block publishes its number', block.packet.fields?.['tftp.block'], 1);
  check('...and its payload size', block.packet.fields?.['tftp.data_length'], 512);

  console.log();
  if (failureCount() > 0) {
    console.log(`${failureCount()} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All TFTP checks passed.');
  process.exit(0);
}

main();
