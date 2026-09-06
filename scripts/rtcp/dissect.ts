/**
 * RTCP, against tshark - and the case for not dissecting RTP.
 *
 *   npx tsx scripts/rtcp/dissect.ts
 *
 * RTCP has no assigned port; it runs on whatever SIP or ICE negotiated. So it
 * is found by content or not at all, which makes it the first real customer of
 * `dissectors/heuristics.ts` and puts the whole weight on its fingerprint being
 * specific enough.
 *
 * Two properties matter more than the field decoding:
 *
 *   - **The lengths must tile the datagram exactly.** Each packet declares its
 *     own size in 32-bit words, and a compound datagram's packets must fill it
 *     with nothing over. Random bytes do not describe their own size correctly
 *     several times in a row, and that - not the two version bits - is what
 *     makes this safe to claim on an arbitrary port.
 *   - **Only some types may open a datagram**, and the set is narrower than
 *     RFC 3550 §6.1's "SR or RR" - it was established by asking tshark one type
 *     at a time, not read off the RFC. 200, 201 and 203-207 lead; a lone Source
 *     Description does not, and comes back from tshark as `UDP`. Reading the
 *     spec alone would have produced a detector both too strict (rejecting a
 *     lone BYE, which tshark accepts) and, in the other direction, unjustified.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { looksLikeRtcp } from '../../src/services/dissectors/rtcp';
import { detectUdpPayload } from '../../src/services/dissectors/heuristics';
import {
  Bytes, check, failureCount, runCases, udpFrame, type SyntheticCase,
} from '../parity/synthetic';

const SSRC = 0xdeadbeef;

const sr = new Bytes().u8(0x80, 200).u16(6).u32(SSRC)
  .u32(0xe0f0d0c0).u32(0x00000000).u32(0x00001388).u32(10).u32(1600).build();

const rr = new Bytes().u8(0x80, 201).u16(1).u32(SSRC).build();

const sdes = (() => {
  const cname = 'alice@example.com';
  const body = new Bytes().u32(SSRC).u8(1, cname.length).ascii(cname).u8(0).build();
  const pad = (4 - (body.length % 4)) % 4;
  const full = new Bytes().raw(body).zeros(pad).build();
  return new Bytes().u8(0x81, 202).u16(full.length / 4).raw(full).build();
})();

const bye = new Bytes().u8(0x81, 203).u16(1).u32(SSRC).build();
const compound = new Bytes().raw(sr).raw(sdes).build();
const srThenBye = new Bytes().raw(sr).raw(bye).build();

const cases: SyntheticCase[] = [
  { name: 'a Sender Report', frame: udpFrame(50001, 50003, sr) },
  { name: 'a Receiver Report', frame: udpFrame(50001, 50003, rr) },
  { name: 'a compound SR then SDES', frame: udpFrame(50001, 50003, compound) },
  { name: 'a compound SR then BYE', frame: udpFrame(50001, 50003, srThenBye) },
  // A lone SDES: tshark shows UDP, so this must too. It is the case that keeps
  // the detector from being more eager than the reference analyzer.
  { name: 'a lone Source Description, which is not claimed', frame: udpFrame(50001, 50003, sdes) },
  // A lone BYE IS claimed, which is what makes the boundary interesting: the
  // rule is not RFC 3550's "must open with SR or RR" but a specific set.
  { name: 'a lone Goodbye', frame: udpFrame(50001, 50003, bye) },
  { name: 'a lone Extended Report', frame: udpFrame(50001, 50003,
      new Bytes().u8(0x80, 207).u16(1).u32(SSRC).build()) },
  // The legacy H.261 types lead nothing, however well formed.
  { name: 'a lone FIR, which is not claimed', frame: udpFrame(50001, 50003,
      new Bytes().u8(0x80, 192).u16(1).u32(SSRC).build()) },
];

async function main(): Promise<void> {
  await runCases(cases);

  // --- the fingerprint --------------------------------------------------------
  check('a Sender Report is RTCP', looksLikeRtcp(sr, 0, sr.length), true);
  check('a compound packet is RTCP', looksLikeRtcp(compound, 0, compound.length), true);
  // The set of types that may LEAD is narrower than the set a compound packet
  // may contain, and narrower than RFC 3550 §6.1 - established one type at a
  // time against tshark rather than read off the RFC.
  check('a lone SDES may not lead', looksLikeRtcp(sdes, 0, sdes.length), false);
  check('a lone BYE may', looksLikeRtcp(bye, 0, bye.length), true);
  const fir = new Bytes().u8(0x80, 192).u16(1).u32(SSRC).build();
  check('a legacy H.261 type may not', looksLikeRtcp(fir, 0, fir.length), false);
  const beyond = new Bytes().u8(0x80, 208).u16(1).u32(SSRC).build();
  check('nor may anything past 207', looksLikeRtcp(beyond, 0, beyond.length), false);

  // Version 1 or 0 is not RTCP however well the rest lines up.
  const version1 = new Bytes().u8(0x40, 200).u16(6).u32(SSRC).zeros(20).build();
  check('version 1 is rejected', looksLikeRtcp(version1, 0, version1.length), false);

  // A packet type outside 192-223 is not RTCP.
  const badType = new Bytes().u8(0x80, 100).u16(6).u32(SSRC).zeros(20).build();
  check('a packet type outside the reserved range is rejected',
    looksLikeRtcp(badType, 0, badType.length), false);

  // The tiling rule: a declared length that leaves bytes over, or runs past the
  // end, is not RTCP. This is the strongest part of the fingerprint.
  const trailing = new Bytes().raw(sr).u8(0, 0, 0, 0).build();
  check('trailing bytes past the declared length are rejected',
    looksLikeRtcp(trailing, 0, trailing.length), false);
  const overlong = new Bytes().u8(0x80, 200).u16(99).u32(SSRC).zeros(20).build();
  check('a length running past the datagram is rejected',
    looksLikeRtcp(overlong, 0, overlong.length), false);
  const truncated = sr.subarray(0, sr.length - 4);
  check('a truncated Sender Report is rejected',
    looksLikeRtcp(truncated, 0, truncated.length), false);

  // --- through the heuristic registry -------------------------------------------
  check('RTCP is dispatched by content, with no port assigned',
    detectUdpPayload(sr, 0, sr.length)?.detector, 'RTCP');

  const frame = udpFrame(50001, 50003, sr);
  const { packet } = decodeRawEthernetPacket(frame, 1, 1_700_000_000_000_000, 0, 0, frame.length);
  check('the protocol chain is right', packet.frameProtocols, ['frame', 'eth', 'ip', 'udp', 'rtcp']);
  check('the SSRC is published', packet.fields?.['rtcp.senderssrc'], SSRC);
  check("the sender's packet count is published", packet.fields?.['rtcp.sender.packetcount'], 10);
  // Which rule claimed it, so a wrong label is traceable.
  check('the match records which detector made it', packet.fields?.['inwire.heuristic'], 'RTCP');

  console.log();
  if (failureCount() > 0) {
    console.log(`${failureCount()} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All RTCP checks passed.');
  process.exit(0);
}

main();
