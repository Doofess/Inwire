/**
 * SIP, against tshark.
 *
 *   npx tsx scripts/sip/dissect.ts
 *
 * Frames are RFC 3261 §24.2's own example call flow, which is the one place a
 * SIP message's exact spelling is published - branch parameters, tags and all.
 * See `scripts/parity/synthetic.ts` for why the oracle matters here.
 *
 * The property most worth pinning is that a **response names the request it
 * answers**: `Status: 200 OK (INVITE)`. That method is read out of the CSeq
 * header, not out of any transaction state, which is what lets one datagram be
 * read on its own - and it is invisible in a test that only checks the status
 * code came back.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { dissectSip, looksLikeSip } from '../../src/services/dissectors/sip';
import {
  Bytes, check, failureCount, runCases, udpFrame, type SyntheticCase,
} from '../parity/synthetic';

const crlf = (...lines: string[]) => new Bytes().ascii(lines.join('\r\n')).build();

const VIA = 'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds';
const FROM = 'From: Alice <sip:alice@example.com>;tag=1928301774';
const TO = 'To: Bob <sip:bob@example.com>';
const CALL_ID = 'Call-ID: a84b4c76e66710';

const invite = crlf(
  'INVITE sip:bob@example.com SIP/2.0', VIA, 'Max-Forwards: 70', TO, FROM, CALL_ID,
  'CSeq: 314159 INVITE', 'Contact: <sip:alice@192.0.2.1>',
  'User-Agent: Inwire-Test/1.0', 'Content-Length: 0', '', '');

const ringing = crlf(
  'SIP/2.0 180 Ringing', VIA, `${TO};tag=a6c85cf`, FROM, CALL_ID,
  'CSeq: 314159 INVITE', 'Content-Length: 0', '', '');

const ok = crlf(
  'SIP/2.0 200 OK', VIA, `${TO};tag=a6c85cf`, FROM, CALL_ID,
  'CSeq: 314159 INVITE', 'Contact: <sip:bob@192.0.2.2>', 'Content-Length: 0', '', '');

const ack = crlf(
  'ACK sip:bob@192.0.2.2 SIP/2.0', VIA, `${TO};tag=a6c85cf`, FROM, CALL_ID,
  'CSeq: 314159 ACK', 'Content-Length: 0', '', '');

const bye = crlf(
  'BYE sip:alice@192.0.2.1 SIP/2.0', VIA, FROM, `${TO};tag=a6c85cf`, CALL_ID,
  'CSeq: 231 BYE', 'Content-Length: 0', '', '');

const registerMsg = crlf(
  'REGISTER sip:example.com SIP/2.0', VIA, TO, FROM, CALL_ID,
  'CSeq: 1 REGISTER', 'Expires: 3600', 'Content-Length: 0', '', '');

// A failure response, so the reason phrase is something other than "OK".
const notFound = crlf(
  'SIP/2.0 404 Not Found', VIA, `${TO};tag=a6c85cf`, FROM, CALL_ID,
  'CSeq: 314159 INVITE', 'Content-Length: 0', '', '');

// A multi-word reason phrase after a three-digit code, which a parser that
// takes only the third token truncates to "Server".
const unavailable = crlf(
  'SIP/2.0 503 Service Unavailable', VIA, `${TO};tag=a6c85cf`, FROM, CALL_ID,
  'CSeq: 314159 INVITE', 'Content-Length: 0', '', '');

const cases: SyntheticCase[] = [
  { name: 'an INVITE', frame: udpFrame(5060, 5060, invite) },
  { name: 'a 180 Ringing', frame: udpFrame(5060, 5060, ringing) },
  { name: 'a 200 OK', frame: udpFrame(5060, 5060, ok) },
  { name: 'an ACK', frame: udpFrame(5060, 5060, ack) },
  { name: 'a BYE', frame: udpFrame(5060, 5060, bye) },
  { name: 'a REGISTER', frame: udpFrame(5060, 5060, registerMsg) },
  { name: 'a 404 Not Found', frame: udpFrame(5060, 5060, notFound) },
  { name: 'a 503 with a two-word reason', frame: udpFrame(5060, 5060, unavailable) },

  // The rule for naming the answered request is "status is exactly 200", not
  // "2xx" - which is only visible with a second 2xx to compare against.
  { name: 'a 202 Accepted, which names no method', frame: udpFrame(5060, 5060, crlf(
      'SIP/2.0 202 Accepted', VIA, `${TO};tag=a6c85cf`, FROM, CALL_ID,
      'CSeq: 314159 INVITE', 'Content-Length: 0', '', '')) },
  { name: 'a 100 Trying', frame: udpFrame(5060, 5060, crlf(
      'SIP/2.0 100 Trying', VIA, `${TO};tag=a6c85cf`, FROM, CALL_ID,
      'CSeq: 314159 INVITE', 'Content-Length: 0', '', '')) },
  { name: 'a 200 OK to a BYE names BYE', frame: udpFrame(5060, 5060, crlf(
      'SIP/2.0 200 OK', VIA, `${TO};tag=a6c85cf`, FROM, CALL_ID,
      'CSeq: 231 BYE', 'Content-Length: 0', '', '')) },

  // The REGISTER binding summary, which is the one place the Info column says
  // what a message DOES rather than what it is.
  { name: 'a REGISTER with one Contact', frame: udpFrame(5060, 5060, crlf(
      'REGISTER sip:example.com SIP/2.0', VIA, TO, FROM, CALL_ID, 'CSeq: 1 REGISTER',
      'Contact: <sip:alice@192.0.2.1>', 'Expires: 3600', 'Content-Length: 0', '', '')) },
  { name: 'a REGISTER that removes all bindings', frame: udpFrame(5060, 5060, crlf(
      'REGISTER sip:example.com SIP/2.0', VIA, TO, FROM, CALL_ID, 'CSeq: 1 REGISTER',
      'Contact: *', 'Expires: 0', 'Content-Length: 0', '', '')) },
  { name: 'a 200 OK to a REGISTER counts bindings', frame: udpFrame(5060, 5060, crlf(
      'SIP/2.0 200 OK', VIA, `${TO};tag=a6c85cf`, FROM, CALL_ID, 'CSeq: 1 REGISTER',
      'Content-Length: 0', '', '')) },
];

async function main(): Promise<void> {
  await runCases(cases);

  // --- the detector ------------------------------------------------------------
  //
  // SIP and HTTP share `OPTIONS`, so the method cannot be the test - the
  // version token is.
  const httpOptions = new Bytes().ascii('OPTIONS / HTTP/1.1\r\nHost: example.com\r\n\r\n').build();
  check('the detector accepts a SIP request', looksLikeSip(invite, 0, invite.length), true);
  check('...and a SIP response', looksLikeSip(ok, 0, ok.length), true);
  check('...and rejects HTTP OPTIONS, which shares the method',
    looksLikeSip(httpOptions, 0, httpOptions.length), false);
  const notAMethod = new Bytes().ascii('WIBBLE sip:x SIP/2.0\r\n\r\n').build();
  check('...and rejects an unknown method', looksLikeSip(notAMethod, 0, notAMethod.length), false);
  const badStatus = new Bytes().ascii('SIP/2.0 999 Nope\r\n\r\n').build();
  check('...and rejects a status code outside 100-699',
    looksLikeSip(badStatus, 0, badStatus.length), false);
  check('...and rejects a datagram with no line ending at all',
    looksLikeSip(new Bytes().ascii('INVITE sip:x SIP/2.0').build(), 0, 20), false);

  // --- the CSeq method, which is what names the answered request ---------------
  const okResult = dissectSip(ok, 0, ok.length);
  check('a response names the request it answers', okResult?.info, 'Status: 200 OK (INVITE) | ');
  check('...from the CSeq header', okResult?.fields['sip.CSeq'], '314159 INVITE');
  // A response with no CSeq must not invent one, nor print an empty bracket.
  const noCseq = crlf('SIP/2.0 200 OK', VIA, CALL_ID, 'Content-Length: 0', '', '');
  check('a response with no CSeq names no method',
    dissectSip(noCseq, 0, noCseq.length)?.info, 'Status: 200 OK | ');

  // --- what reaches the rest of the app ------------------------------------------
  const frame = udpFrame(5060, 5060, invite);
  const { packet } = decodeRawEthernetPacket(frame, 1, 1_700_000_000_000_000, 0, 0, frame.length);
  check('the protocol chain is right', packet.frameProtocols, ['frame', 'eth', 'ip', 'udp', 'sip']);
  check('the method is published', packet.fields?.['sip.Method'], 'INVITE');
  check('the request URI is published', packet.fields?.['sip.r-uri'], 'sip:bob@example.com');
  // The Call-ID ties every frame of one call together, which is the filter
  // anybody reading a capture of a call actually types.
  check('the Call-ID is published', packet.fields?.['sip.Call-ID'], 'a84b4c76e66710');
  check('the From header is published',
    packet.fields?.['sip.From'], 'Alice <sip:alice@example.com>;tag=1928301774');
  check('the User-Agent is published', packet.fields?.['sip.User-Agent'], 'Inwire-Test/1.0');

  const layer = packet.layers.find((l) => l.name === 'Session Initiation Protocol');
  check('the tree carries a SIP layer', layer !== undefined, true);
  const headers = layer?.fields.find((f) => f.name === 'Message Header')?.children ?? [];
  check('every header is a row', headers.length, 9);

  // The trailing space after the pipe is part of Wireshark's format, not an
  // artefact of joining - and it is exactly what a `trimEnd()` in the harness
  // would have forgiven. Stated here so it cannot be "tidied" later.
  check('the Info column ends with a space after the pipe',
    dissectSip(invite, 0, invite.length)?.info.endsWith(' | '), true);

  console.log();
  if (failureCount() > 0) {
    console.log(`${failureCount()} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All SIP checks passed.');
  process.exit(0);
}

main();
