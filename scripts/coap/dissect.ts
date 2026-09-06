/**
 * CoAP, against tshark.
 *
 *   npx tsx scripts/coap/dissect.ts
 *
 * Two things here are easy to get wrong in ways that still look right.
 *
 * The **code** is one byte read as `class.detail`: 69 is `2.05 Content`, not
 * 69 and not 2.5. A formatter that drops the zero padding produces `2.5`,
 * which is a different response code that also exists.
 *
 * **Options are deltas.** Each option's number is the previous one's plus the
 * delta in its own header, so a single misread option does not corrupt one
 * row - it shifts the number of every option after it, silently renaming
 * Uri-Path to something else. The multi-option cases below are what catch that;
 * a single-option frame cannot.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { dissectCoap } from '../../src/services/dissectors/coap';
import {
  Bytes, check, failureCount, runCases, udpFrame, type SyntheticCase,
} from '../parity/synthetic';

const CON = 0, NON = 1, ACK = 2, RST = 3;

/** A message with a token length of zero and whatever options are given. */
function message(type: number, code: number, mid: number, options: Uint8Array = new Uint8Array()):
  Uint8Array {
  return new Bytes().u8(0x40 | (type << 4), code).u16(mid).raw(options).build();
}

/** One option, delta-encoded against the previous option number. */
function option(delta: number, value: string): Uint8Array {
  return new Bytes().u8((delta << 4) | value.length).ascii(value).build();
}

const uriPath = (...segments: string[]): Uint8Array => {
  const out: number[] = [];
  segments.forEach((segment, i) => {
    // Uri-Path is option 11; the first carries a delta of 11 from zero and
    // every one after it a delta of 0.
    out.push(...option(i === 0 ? 11 : 0, segment));
  });
  return Uint8Array.from(out);
};

const cases: SyntheticCase[] = [
  { name: 'a confirmable GET', frame: udpFrame(50000, 5683, message(CON, 1, 0x1234, uriPath('temp'))) },
  { name: 'a non-confirmable PUT', frame: udpFrame(50000, 5683, message(NON, 3, 0x1234, uriPath('led'))) },
  { name: 'a POST', frame: udpFrame(50000, 5683, message(CON, 2, 0x0001, uriPath('actuators', 'led'))) },
  { name: 'a DELETE', frame: udpFrame(50000, 5683, message(CON, 4, 0x0002, uriPath('obs'))) },
  // A multi-segment path, which is where a delta walk shifts if it is wrong.
  { name: 'a three-segment path',
    frame: udpFrame(50000, 5683, message(CON, 1, 0x0003, uriPath('a', 'b', 'c'))) },
  { name: 'a GET with no path at all', frame: udpFrame(50000, 5683, message(CON, 1, 0x0004)) },

  // Responses. The code is class.detail and never a bare number.
  { name: 'a 2.05 Content', frame: udpFrame(5683, 50000, message(ACK, 69, 0x1234)) },
  { name: 'a 2.01 Created', frame: udpFrame(5683, 50000, message(ACK, 65, 0x1234)) },
  { name: 'a 4.04 Not Found', frame: udpFrame(5683, 50000, message(ACK, 132, 0x1234)) },
  { name: 'a 4.00 Bad Request', frame: udpFrame(5683, 50000, message(ACK, 128, 0x1234)) },
  { name: 'a 5.00 Internal Server Error', frame: udpFrame(5683, 50000, message(ACK, 160, 0x1234)) },

  // An empty message: code 0 names no method and no status.
  { name: 'an empty acknowledgement', frame: udpFrame(5683, 50000, message(ACK, 0, 0x1234)) },
  { name: 'a reset', frame: udpFrame(5683, 50000, message(RST, 0, 0x1234)) },

  // A token, which is how a response is matched to a request that was not an
  // acknowledgement of the same message id.
  { name: 'a message carrying a token', frame: udpFrame(50000, 5683, new Bytes()
      .u8(0x44, 0x01).u16(0x0005).u8(0xde, 0xad, 0xbe, 0xef)
      .raw(uriPath('temp')).build()) },
  // The same token on a response, which is where it earns its keep: a separate
  // acknowledgement carries no path to match on.
  { name: 'a response carrying a token', frame: udpFrame(5683, 50000, new Bytes()
      .u8(0x54, 69).u16(0x0005).u8(0xde, 0xad, 0xbe, 0xef).build()) },
];

async function main(): Promise<void> {
  await runCases(cases);

  // --- the code is class.detail ------------------------------------------------
  //
  // A formatter that does not pad produces `2.5`, which is a real and different
  // code, so this is checked at the boundary rather than on a round number.
  const content = message(ACK, 69, 1);
  check('69 renders as 2.05', dissectCoap(content, 0, content.length)?.info,
    'ACK, MID:1, 2.05 Content');
  const changed = message(ACK, 68, 1);
  check('...and 68 as 2.04', dissectCoap(changed, 0, changed.length)?.info,
    'ACK, MID:1, 2.04 Changed');

  // --- options are deltas --------------------------------------------------------
  const threeSegments = message(CON, 1, 1, uriPath('a', 'b', 'c'));
  check('a three-segment path assembles in order',
    dissectCoap(threeSegments, 0, threeSegments.length)?.fields['coap.opt.uri_path'], '/a/b/c');

  // --- what is not CoAP ------------------------------------------------------------
  const version0 = message(CON, 1, 1);
  version0[0] = 0x00;
  check('version 0 is declined', dissectCoap(version0, 0, version0.length), null);
  // RFC 7252 §3: a token length of 9-15 is a format error and must be refused.
  // This is most of what keeps CoAP off arbitrary UDP.
  const badTokenLength = message(CON, 1, 1);
  badTokenLength[0] = 0x49;
  check('a token length above 8 is declined',
    dissectCoap(badTokenLength, 0, badTokenLength.length), null);
  const tokenPastEnd = new Bytes().u8(0x48, 0x01).u16(1).u8(0xde, 0xad).build();
  check('a token running past the datagram is declined',
    dissectCoap(tokenPastEnd, 0, tokenPastEnd.length), null);
  const optionPastEnd = new Bytes().u8(0x40, 0x01).u16(1).u8(0xbf).build();
  check('an option length running past the datagram is declined',
    dissectCoap(optionPastEnd, 0, optionPastEnd.length), null);
  check('three bytes are not a header', dissectCoap(new Bytes().u8(0x40, 1, 0).build(), 0, 3), null);

  // --- what reaches the rest of the app ----------------------------------------------
  const frame = udpFrame(50000, 5683, message(CON, 1, 0x1234, uriPath('sensors', 'temp')));
  const { packet } = decodeRawEthernetPacket(frame, 1, 1_700_000_000_000_000, 0, 0, frame.length);
  check('the protocol chain is right', packet.frameProtocols, ['frame', 'eth', 'ip', 'udp', 'coap']);
  check('the path is published', packet.fields?.['coap.opt.uri_path'], '/sensors/temp');
  check('the message id is published', packet.fields?.['coap.mid'], 0x1234);
  check('the code is published', packet.fields?.['coap.code'], 1);

  console.log();
  if (failureCount() > 0) {
    console.log(`${failureCount()} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All CoAP checks passed.');
  process.exit(0);
}

main();
