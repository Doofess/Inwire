/**
 * Syslog and RADIUS, against tshark.
 *
 *   npx tsx scripts/syslog/dissect.ts
 *
 * Two small UDP protocols in one script because they are tested the same way
 * and neither is large enough to be worth its own file. Frames are built from
 * RFC 3164 / RFC 5424 and RFC 2865's own examples and handed to tshark - see
 * `scripts/parity/synthetic.ts` for why the oracle matters here.
 *
 * The property under test in both cases is a *split*: a syslog priority is one
 * number that is really two (facility and severity), and a RADIUS attribute's
 * length byte counts itself. Both are the kind of arithmetic that produces
 * confident, plausible, wrong output rather than an obvious failure.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { dissectSyslog, looksLikeSyslog } from '../../src/services/dissectors/syslog';
import { looksLikeRadius } from '../../src/services/dissectors/radius';
import {
  Bytes, check, failureCount, runCases, udpFrame, type SyntheticCase,
} from '../parity/synthetic';

const ascii = (text: string) => new Bytes().ascii(text).build();

/** RFC 3164 §5.4's own example message. */
const RFC3164 = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";
/** RFC 5424 §6.5's example 3, structured data and all. */
const RFC5424 = '<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 '
  + '[exampleSDID@32473 iut="3" eventSource="Application"] BOMAn application event log entry...';

const radiusRequest = (() => {
  const attrs = new Bytes()
    .u8(1, 7).ascii('alice')          // User-Name, length counts these two bytes
    .u8(4, 6).ipv4('192.0.2.1')       // NAS-IP-Address
    .u8(5, 6).u32(7)                  // NAS-Port
    .u8(2, 18).raw(new Array(16).fill(0x5a))   // User-Password: encrypted, never text
    .build();
  return new Bytes().u8(1, 42).u16(20 + attrs.length)
    .raw(new Array(16).fill(0xaa)).raw(attrs).build();
})();

const radiusAccept = (() => {
  const attrs = new Bytes().u8(8, 6).ipv4('192.0.2.50').u8(27, 6).u32(3600).build();
  return new Bytes().u8(2, 42).u16(20 + attrs.length)
    .raw(new Array(16).fill(0xbb)).raw(attrs).build();
})();

const radiusReject = new Bytes().u8(3, 99).u16(20).raw(new Array(16).fill(0xcc)).build();

const cases: SyntheticCase[] = [
  { name: 'a syslog message, RFC 3164', frame: udpFrame(50000, 514, ascii(RFC3164)) },
  { name: 'a syslog message, RFC 5424', frame: udpFrame(50000, 514, ascii(RFC5424)) },
  { name: 'a syslog message at INFO', frame: udpFrame(50000, 514, ascii('<14>Jan  1 00:00:00 host app: hello')) },
  // Facility 0 severity 0: the value is `<0>`, which a parser that treats a
  // falsy priority as "absent" drops entirely.
  { name: 'a kernel emergency', frame: udpFrame(50000, 514, ascii('<0>kernel panic')) },
  // The largest legal priority, LOCAL7.DEBUG.
  { name: 'the highest legal priority', frame: udpFrame(50000, 514, ascii('<191>last one')) },

  { name: 'a RADIUS Access-Request', frame: udpFrame(50000, 1812, radiusRequest) },
  { name: 'a RADIUS Access-Accept', frame: udpFrame(1812, 50000, radiusAccept) },
  { name: 'a RADIUS Access-Reject with no attributes', frame: udpFrame(1812, 50000, radiusReject) },
];

async function main(): Promise<void> {
  await runCases(cases);

  // --- the priority split, unit level -----------------------------------------
  const parse = (text: string) => {
    const bytes = ascii(text);
    return dissectSyslog(bytes, 0, bytes.length);
  };
  check('34 is AUTH at CRIT', parse('<34>x')?.info, 'AUTH.CRIT: x');
  check('0 is KERN at EMERG', parse('<0>x')?.info, 'KERN.EMERG: x');
  check('191 is LOCAL7 at DEBUG', parse('<191>x')?.info, 'LOCAL7.DEBUG: x');
  check('the facility is the priority over eight', parse('<34>x')?.fields['syslog.facility'], 4);
  check('...and the level is the remainder', parse('<34>x')?.fields['syslog.level'], 2);

  // --- what is not syslog ------------------------------------------------------
  //
  // `looksLikeSyslog` is offered to the heuristic path, so the shape of its
  // rejections is what stops it claiming other protocols' payloads.
  check('a priority past 191 is not syslog', looksLikeSyslog(ascii('<192>x'), 0, 6), false);
  check('an unterminated priority is not syslog', looksLikeSyslog(ascii('<34 x'), 0, 5), false);
  check('four digits is not a priority', looksLikeSyslog(ascii('<1234>x'), 0, 7), false);
  check('an empty priority is not syslog', looksLikeSyslog(ascii('<>x'), 0, 3), false);
  check('text with no priority at all is not syslog', looksLikeSyslog(ascii('hello'), 0, 5), false);

  // --- RADIUS attribute walking -------------------------------------------------
  const frame = udpFrame(50000, 1812, radiusRequest);
  const { packet } = decodeRawEthernetPacket(frame, 1, 1_700_000_000_000_000, 0, 0, frame.length);
  check('the RADIUS protocol chain is right',
    packet.frameProtocols, ['frame', 'eth', 'ip', 'udp', 'radius']);
  check('the user name is published', packet.fields?.['radius.username'], 'alice');
  check('the identifier is published', packet.fields?.['radius.id'], 42);

  const radiusLayer = packet.layers.find((l) => l.name === 'RADIUS Protocol');
  const avps = radiusLayer?.fields.find((f) => f.name === 'Attribute Value Pairs')?.children ?? [];
  // Four attributes, and the count is the assertion: a length byte read as the
  // value's own length walks two bytes further each time and finds three, or
  // five, or runs off the end - never four.
  check('every attribute is walked', avps.length, 4);
  check('an address attribute renders as an address',
    avps.find((a) => a.name.includes('NAS-IP-Address'))?.value, '192.0.2.1');
  check('an integer attribute renders as a number',
    avps.find((a) => a.name.includes('NAS-Port'))?.value, '7');
  // The credential is never rendered as text, whatever the bytes happen to be.
  check('User-Password shows its length and not its bytes',
    avps.find((a) => a.name.includes('User-Password'))?.value, '16 bytes');

  check('a RADIUS message must declare its own length',
    looksLikeRadius(new Bytes().u8(1, 42).u16(999).raw(new Array(16).fill(0)).build(), 0, 20), false);
  check('...and carry a known code',
    looksLikeRadius(new Bytes().u8(200, 42).u16(20).raw(new Array(16).fill(0)).build(), 0, 20), false);
  check('a well-formed one is accepted', looksLikeRadius(radiusReject, 0, radiusReject.length), true);

  console.log();
  if (failureCount() > 0) {
    console.log(`${failureCount()} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All syslog and RADIUS checks passed.');
  process.exit(0);
}

main();
