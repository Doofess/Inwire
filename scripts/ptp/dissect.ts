/**
 * PTP, against tshark.
 *
 *   npx tsx scripts/ptp/dissect.ts
 *
 * The header is fixed and the Info line is just the message name, so what is
 * actually under test is which **messages exist** and which do not. The type
 * is a four-bit field with sixteen values and only ten assigned, and the gaps
 * are not contiguous - 4 through 7 are unassigned and 8 through 13 are - so a
 * table written as a range would name four messages that do not exist.
 *
 * The split across two ports is asserted too, because it is the one thing
 * about PTP that a reader can act on: event messages are hardware-timestamped
 * and go to 319, everything else goes to 320.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { dissectPtp } from '../../src/services/dissectors/ptp';
import {
  Bytes, check, failureCount, runCases, udpFrame, type SyntheticCase,
} from '../parity/synthetic';

/** The 34-byte common header, then a body padded to the declared length. */
function message(messageType: number, length: number, sequenceId = 1): Uint8Array {
  return new Bytes()
    .u8(messageType, 0x02)          // majorSdoId|messageType, minorVersion|versionPTP
    .u16(length)
    .u8(0, 0)                       // domainNumber, minorSdoId
    .u16(0x0000)                    // flags
    .zeros(8)                       // correctionField
    .zeros(4)                       // messageTypeSpecific
    .raw([0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55])   // clockIdentity
    .u16(1)                         // portNumber
    .u16(sequenceId)
    .u8(0, 0)                       // controlField, logMessageInterval
    .zeros(Math.max(0, length - 34))
    .build();
}

/** A Management message: the header, the management body, then its TLV. */
function management(action: number, managementId: number): Uint8Array {
  return new Bytes()
    .raw(message(0x0d, 54).subarray(0, 34))
    .zeros(10).u8(0, 0, action, 0)         // targetPortIdentity, hops, action, reserved
    .u16(0x0001).u16(2).u16(managementId)  // MANAGEMENT TLV: type, length, id
    .build();
}

const cases: SyntheticCase[] = [
  // Event messages, on port 319.
  { name: 'a Sync', frame: udpFrame(319, 319, message(0x00, 44)) },
  { name: 'a Delay_Req', frame: udpFrame(319, 319, message(0x01, 44)) },
  { name: 'a Peer_Delay_Req', frame: udpFrame(319, 319, message(0x02, 54)) },
  { name: 'a Peer_Delay_Resp', frame: udpFrame(319, 319, message(0x03, 54)) },
  // General messages, on port 320.
  { name: 'a Follow_Up', frame: udpFrame(320, 320, message(0x08, 44)) },
  { name: 'a Delay_Resp', frame: udpFrame(320, 320, message(0x09, 54)) },
  { name: 'a Peer_Delay_Resp_Follow_Up', frame: udpFrame(320, 320, message(0x0a, 54)) },
  { name: 'an Announce', frame: udpFrame(320, 320, message(0x0b, 64)) },
  { name: 'a Signaling', frame: udpFrame(320, 320, message(0x0c, 44)) },
  // Management carries a mandatory TLV after its own body; padding alone is
  // malformed, which tshark says so this frame is built properly.
  { name: 'a Management GET', frame: udpFrame(320, 320, management(0, 0x0000)) },
  // Management's Info names what is being asked and what is being done, which
  // is a grammar no other message has - so each half is varied against a
  // fixed other half.
  { name: 'a Management SET', frame: udpFrame(320, 320, management(1, 0x0000)) },
  { name: 'a Management RESPONSE', frame: udpFrame(320, 320, management(2, 0x0000)) },
  { name: 'a Management COMMAND', frame: udpFrame(320, 320, management(3, 0x2005)) },
  { name: 'a GET of the default dataset', frame: udpFrame(320, 320, management(0, 0x2000)) },
  { name: 'a GET of the parent dataset', frame: udpFrame(320, 320, management(0, 0x2002)) },
  { name: 'a GET of a transparent clock dataset',
    frame: udpFrame(320, 320, management(0, 0x4000)) },
  // An id nobody has assigned, which the reference analyzer reports in decimal.
  { name: 'a GET of an unassigned id', frame: udpFrame(320, 320, management(0, 0x1234)) },
  { name: 'an action nobody has assigned', frame: udpFrame(320, 320, management(5, 0x0000)) },
  // A sequence id that is not 1, so the field is read rather than defaulted.
  { name: 'a Sync with a high sequence id', frame: udpFrame(319, 319, message(0x00, 44, 40000)) },
];

async function main(): Promise<void> {
  await runCases(cases);

  // --- the unassigned types are not messages -------------------------------------
  //
  // 4-7 are unassigned and 8-13 are assigned, so a table written as a range
  // would invent four messages. Each gap is checked rather than the boundary.
  for (const type of [0x04, 0x05, 0x06, 0x07, 0x0e, 0x0f]) {
    const bytes = message(type, 44);
    check(`message type 0x${type.toString(16)} is not a PTP message`,
      dissectPtp(bytes, 0, bytes.length), null);
  }

  // --- which port a message belongs on ---------------------------------------------
  const sync = message(0x00, 44);
  const read = dissectPtp(sync, 0, sync.length);
  const messageClass = read?.layer.fields.find((f) => f.name === '[Message class]');
  check('a Sync is an event message', messageClass?.value, 'Event');
  const followUp = message(0x08, 44);
  const general = dissectPtp(followUp, 0, followUp.length);
  check('...and a Follow_Up is general',
    general?.layer.fields.find((f) => f.name === '[Message class]')?.value, 'General');

  // --- what is not PTP -----------------------------------------------------------------
  const version1 = message(0x00, 44);
  version1[1] = 0x01;
  check('PTPv1 is declined rather than half-read', dissectPtp(version1, 0, version1.length), null);
  // The declared length is the fingerprint: the type nibble alone matches far
  // too much, and a length that does not describe the datagram is not PTP.
  const shortLength = message(0x00, 44);
  shortLength[2] = 0; shortLength[3] = 20;
  check('a declared length under the header is declined',
    dissectPtp(shortLength, 0, shortLength.length), null);
  const longLength = message(0x00, 44);
  longLength[2] = 0x01; longLength[3] = 0x00;
  check('...and one past the datagram', dissectPtp(longLength, 0, longLength.length), null);
  const truncated = sync.subarray(0, 30);
  check('a truncated header is declined', dissectPtp(truncated, 0, truncated.length), null);

  // --- what reaches the rest of the app --------------------------------------------------
  const frame = udpFrame(319, 319, message(0x00, 44, 4242));
  const { packet } = decodeRawEthernetPacket(frame, 1, 1_700_000_000_000_000, 0, 0, frame.length);
  check('the protocol chain is right', packet.frameProtocols, ['frame', 'eth', 'ip', 'udp', 'ptp']);
  check('the message type is published', packet.fields?.['ptp.v2.messagetype'], 0);
  check('the sequence id is published', packet.fields?.['ptp.v2.sequenceid'], 4242);
  check('the source clock identity is published',
    packet.fields?.['ptp.v2.clockidentity'], '00:11:22:ff:fe:33:44:55');

  console.log();
  if (failureCount() > 0) {
    console.log(`${failureCount()} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All PTP checks passed.');
  process.exit(0);
}

main();
