/**
 * SNMP and the BER reader under it, against tshark.
 *
 *   npx tsx scripts/snmp/dissect.ts
 *
 * The BER half is the reason this file is longer than the protocol warrants.
 * `dissectors/ber.ts` is meant to carry LDAP and Kerberos later, and its three
 * error-prone pieces - long-form lengths, the first-two-arcs OID rule, and
 * signed minimal integers - all fail *quietly*: they produce a value, it is
 * simply the wrong one. So they are pinned at unit level here as well as
 * through the round trip.
 *
 * Frames are built from the RFCs' own layouts and checked against tshark; see
 * `scripts/parity/synthetic.ts`.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { looksLikeSnmp } from '../../src/services/dissectors/snmp';
import {
  BER_TAG, berChildren, berInteger, berOid, berString, readBer,
} from '../../src/services/dissectors/ber';
import {
  check, failureCount, runCases, udpFrame, type SyntheticCase,
} from '../parity/synthetic';

// --- BER builders, written here so the test encodes independently ------------

const tlv = (tag: number, body: number[]): number[] => {
  if (body.length < 0x80) return [tag, body.length, ...body];
  // Long form: 0x80|n, then n bytes of length. Exercised by the big-string case.
  const len: number[] = [];
  for (let v = body.length; v > 0; v = Math.floor(v / 256)) len.unshift(v & 0xff);
  return [tag, 0x80 | len.length, ...len, ...body];
};
const int = (v: number): number[] => {
  if (v === 0) return tlv(BER_TAG.INTEGER, [0]);
  const out: number[] = [];
  for (let n = v; n > 0; n = Math.floor(n / 256)) out.unshift(n & 0xff);
  // A leading bit of 1 would read as negative, so BER pads with a zero byte.
  if (out[0] & 0x80) out.unshift(0);
  return tlv(BER_TAG.INTEGER, out);
};
const str = (s: string) => tlv(BER_TAG.OCTET_STRING, [...s].map((c) => c.charCodeAt(0)));
const NUL = [BER_TAG.NULL, 0x00];
const oid = (...body: number[]) => tlv(BER_TAG.OID, body);

const SYS_DESCR = oid(0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00);   // 1.3.6.1.2.1.1.1.0
const IF_NUMBER = oid(0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x01, 0x00);   // 1.3.6.1.2.1.2.1.0

const varbind = (name: number[], value: number[]) => tlv(BER_TAG.SEQUENCE, [...name, ...value]);
const varbinds = (...vbs: number[][]) => tlv(BER_TAG.SEQUENCE, vbs.flat());

const message = (version: number, community: string, pduTag: number, pduBody: number[]) =>
  Uint8Array.from(tlv(BER_TAG.SEQUENCE, [...int(version), ...str(community), ...tlv(pduTag, pduBody)]));

const stdPdu = (reqId: number, vbs: number[]) => [...int(reqId), ...int(0), ...int(0), ...vbs];

const cases: SyntheticCase[] = [
  { name: 'a get-request', frame: udpFrame(50000, 161,
      message(0, 'public', 0xa0, stdPdu(0x162e, varbinds(varbind(SYS_DESCR, NUL))))) },
  { name: 'a get-next-request', frame: udpFrame(50000, 161,
      message(0, 'public', 0xa1, stdPdu(0x162f, varbinds(varbind(SYS_DESCR, NUL))))) },
  { name: 'a get-response carrying a string', frame: udpFrame(161, 50000,
      message(0, 'public', 0xa2, stdPdu(0x162e, varbinds(varbind(SYS_DESCR, str('Cisco IOS')))))) },
  { name: 'a set-request', frame: udpFrame(50000, 161,
      message(1, 'private', 0xa3, stdPdu(0x1630, varbinds(varbind(SYS_DESCR, str('new name')))))) },
  { name: 'a getBulkRequest', frame: udpFrame(50000, 161,
      message(1, 'public', 0xa5,
        [...int(0x1631), ...int(0), ...int(10), ...varbinds(varbind(SYS_DESCR, NUL))])) },
  { name: 'an snmpV2-trap', frame: udpFrame(50000, 162,
      message(1, 'public', 0xa7,
        stdPdu(0x1632, varbinds(varbind(SYS_DESCR, NUL), varbind(IF_NUMBER, NUL))))) },
  // Every varbind's OID reaches the Info column, not just the first.
  { name: 'two variable bindings', frame: udpFrame(50000, 161,
      message(1, 'public', 0xa0,
        stdPdu(0x1633, varbinds(varbind(SYS_DESCR, NUL), varbind(IF_NUMBER, NUL))))) },
  { name: 'an error response', frame: udpFrame(161, 50000,
      message(0, 'public', 0xa2,
        [...int(0x1634), ...int(2), ...int(1), ...varbinds(varbind(SYS_DESCR, NUL))])) },
  // A value past 127 bytes, which forces BER's long-form length. A reader
  // handling only the short form gets every byte after this wrong.
  { name: 'a response needing a long-form length', frame: udpFrame(161, 50000,
      message(0, 'public', 0xa2,
        stdPdu(0x1635, varbinds(varbind(SYS_DESCR, str('D'.repeat(200))))))) },
];

async function main(): Promise<void> {
  await runCases(cases);

  // --- BER, at unit level -----------------------------------------------------
  const read = (bytes: number[]) => {
    const b = Uint8Array.from(bytes);
    return { b, v: readBer(b, 0, b.length) };
  };

  // The first byte of an OID is TWO arcs: 40 * x + y. 0x2b is 1.3.
  const oidCase = read(oid(0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00));
  check('an OID\'s first byte is two arcs', berOid(oidCase.b, oidCase.v!), '1.3.6.1.2.1.1.1.0');
  // An arc above 127 needs base-128 continuation. 1.2.840.113549 is RSA's.
  const bigArc = read(oid(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d));
  check('an arc past 127 is base-128 with a continuation bit',
    berOid(bigArc.b, bigArc.v!), '1.2.840.113549');
  // 2.x is the one prefix where the second arc may exceed 39, so the
  // `40 * x + y` division has to be clamped rather than trusted.
  const joint = read(oid(0x81, 0x34, 0x03));
  check('a 2.x OID does not lose its second arc to the division',
    berOid(joint.b, joint.v!), '2.100.3');

  // Long form: 0x81 0xc8 is "one length byte follows, value 200".
  const long = read(tlv(BER_TAG.OCTET_STRING, new Array(200).fill(0x41)));
  check('a long-form length is read', long.v?.contentEnd! - long.v?.contentStart!, 200);
  check('...and the value comes back whole', berString(long.b, long.v!).length, 200);

  // Signed, minimal, and the padding byte that keeps a big positive positive.
  const positive = read(int(255));
  check('a padded positive integer is not negative', berInteger(positive.b, positive.v!), 255);
  const negative = read([BER_TAG.INTEGER, 1, 0xff]);
  check('a one-byte 0xff is -1', berInteger(negative.b, negative.v!), -1);
  const zero = read(int(0));
  check('zero survives', berInteger(zero.b, zero.v!), 0);

  // Malformed input declines rather than throwing - these bytes come off a wire.
  check('a length past the buffer is refused', readBer(Uint8Array.from([0x04, 0x7f]), 0, 2), null);
  check('an indefinite length is refused', readBer(Uint8Array.from([0x30, 0x80, 0, 0]), 0, 4), null);
  check('a multi-byte tag is refused', readBer(Uint8Array.from([0x1f, 0x01, 0x02]), 0, 3), null);
  check('an empty buffer is refused', readBer(Uint8Array.from([]), 0, 0), null);

  // A run of zero-length values must terminate rather than spin.
  const manyNulls = read(tlv(BER_TAG.SEQUENCE, [...NUL, ...NUL, ...NUL]));
  check('zero-length children do not loop', berChildren(manyNulls.b, manyNulls.v!).length, 3);

  // --- the detector -------------------------------------------------------------
  const get = message(0, 'public', 0xa0, stdPdu(1, varbinds(varbind(SYS_DESCR, NUL))));
  check('the detector accepts SNMP', looksLikeSnmp(get, 0, get.length), true);
  // A SEQUENCE that does not span the payload exactly is not the whole message.
  check('...and rejects a SEQUENCE that under-runs the payload',
    looksLikeSnmp(Uint8Array.from([...get, 0, 0]), 0, get.length + 2), false);
  check('...and rejects an unknown version',
    looksLikeSnmp(message(7, 'public', 0xa0, stdPdu(1, varbinds(varbind(SYS_DESCR, NUL)))), 0, 40), false);

  // --- what reaches the rest of the app -------------------------------------------
  const frame = udpFrame(50000, 161,
    message(1, 'private', 0xa0, stdPdu(0x162e, varbinds(varbind(SYS_DESCR, NUL)))));
  const { packet } = decodeRawEthernetPacket(frame, 1, 1_700_000_000_000_000, 0, 0, frame.length);
  check('the protocol chain is right', packet.frameProtocols, ['frame', 'eth', 'ip', 'udp', 'snmp']);
  check('the community string is published', packet.fields?.['snmp.community'], 'private');
  check('the OID is published', packet.fields?.['snmp.name'], '1.3.6.1.2.1.1.1.0');
  check('the request id is published', packet.fields?.['snmp.request_id'], 0x162e);

  // v3's third element is a security header, not a PDU. Half-reading it would
  // put SNMP in the Protocol column over an Info line describing a PDU that was
  // never parsed.
  const v3 = message(3, '', 0xa0, stdPdu(1, varbinds(varbind(SYS_DESCR, NUL))));
  const v3Frame = udpFrame(50000, 161, v3);
  const v3Packet = decodeRawEthernetPacket(v3Frame, 1, 1_700_000_000_000_000, 0, 0, v3Frame.length).packet;
  check('SNMPv3 is declined rather than half-read',
    v3Packet.frameProtocols?.includes('snmp'), false);

  console.log();
  if (failureCount() > 0) {
    console.log(`${failureCount()} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All SNMP and BER checks passed.');
  process.exit(0);
}

main();
