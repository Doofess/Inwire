/**
 * Every content detector must reject every other protocol's payloads.
 *
 *   npx tsx scripts/dissect/heuristics.ts
 *
 * `dissectors/heuristics.ts` claims payloads no port dispatched, and its
 * failure mode is not a missed protocol - it is a **confident wrong label**. A
 * reader who sees "SNMP" in the Protocol column believes it; `50000 → 50001
 * Len=76` at least tells the truth.
 *
 * So the property under test is not "does the detector find its own protocol",
 * which is the easy half and is covered in each protocol's own script. It is
 * the cross product: seven detectors against seven protocols' payloads, plus a
 * corpus of real UDP payloads lifted from the parity fixtures, and the only
 * acceptable answer off the diagonal is `false`.
 *
 * The fixture corpus is what makes this more than a tautology. Hand-written
 * negatives test the cases the author thought of; 15,000 frames of somebody's
 * actual browsing tests the ones they did not.
 */
import { existsSync, readFileSync } from 'node:fs';
import { HEURISTIC_DISSECTORS, detectUdpPayload } from '../../src/services/dissectors/heuristics';
import { PcapService } from '../../src/services/pcapParser';
import { Bytes } from '../parity/synthetic';
import { looksLikeDtls } from '../../src/services/dissectors/dtls';
import { looksLikeRtp } from '../../src/services/dissectors/rtp';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

// --- one real payload per protocol -------------------------------------------

const tlv = (tag: number, body: number[]) => [tag, body.length, ...body];
const nbName = (name: string, suffix: number): number[] => {
  const raw = [...name.toUpperCase().padEnd(15, ' ')].map((c) => c.charCodeAt(0)).concat(suffix);
  const out: number[] = [32];
  for (const b of raw) out.push(0x41 + (b >> 4), 0x41 + (b & 0x0f));
  out.push(0);
  return out;
};

const PAYLOADS: { protocol: string; bytes: Uint8Array }[] = [
  {
    protocol: 'STUN',
    // A Binding Request: type, length, the RFC 5389 magic cookie, then a
    // transaction id.
    bytes: new Bytes().u16(0x0001, 0x0000).u32(0x2112a442)
      .raw(new Array(12).fill(0x11)).build(),
  },
  {
    protocol: 'NTP',
    // LI 0, VN 4, mode 3 (client), then the fixed 48-byte body.
    bytes: new Bytes().u8(0x23, 0x00, 0x06, 0xec).zeros(44).build(),
  },
  {
    protocol: 'RADIUS',
    bytes: new Bytes().u8(1, 42).u16(20).raw(new Array(16).fill(0xaa)).build(),
  },
  {
    protocol: 'SNMP',
    bytes: Uint8Array.from(tlv(0x30, [
      ...tlv(0x02, [0]), ...tlv(0x04, [...'public'].map((c) => c.charCodeAt(0))),
      ...tlv(0xa0, [
        ...tlv(0x02, [0x01]), ...tlv(0x02, [0]), ...tlv(0x02, [0]),
        ...tlv(0x30, tlv(0x30, [...tlv(0x06, [0x2b, 0x06, 0x01]), 0x05, 0x00])),
      ]),
    ])),
  },
  {
    protocol: 'NBNS',
    bytes: new Bytes().u16(0x8f8e).u16(0x0110).u16(1, 0, 0, 0)
      .u8(...nbName('WORKGROUP', 0x00)).u16(0x0020, 0x0001).build(),
  },
  {
    protocol: 'SIP',
    bytes: new Bytes().ascii(
      'INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: x\r\nCSeq: 1 INVITE\r\n\r\n').build(),
  },
  {
    protocol: 'WireGuard',
    // A handshake initiation: type 1, three reserved bytes, the sender index,
    // then 144 bytes of key, encrypted static, timestamp and MACs.
    bytes: new Bytes().u8(1, 0, 0, 0).u8(4, 3, 2, 1).raw(new Array(140).fill(0xa5)).build(),
  },
  {
    protocol: 'Syslog',
    bytes: new Bytes().ascii('<34>Oct 11 22:14:15 host su: message').build(),
  },
];

// --- the cross product --------------------------------------------------------

console.log('Every detector against every protocol\'s payload:\n');
for (const detector of HEURISTIC_DISSECTORS) {
  for (const payload of PAYLOADS) {
    const accepted = detector.looksLike(payload.bytes, 0, payload.bytes.length);
    const shouldAccept = detector.name === payload.protocol;
    check(
      shouldAccept
        ? `${detector.name} accepts its own payload`
        : `${detector.name} rejects ${payload.protocol}`,
      accepted, shouldAccept,
    );
  }
}

// The dispatcher must return the right one, not merely some one.
console.log();
for (const payload of PAYLOADS) {
  const match = detectUdpPayload(payload.bytes, 0, payload.bytes.length);
  check(`${payload.protocol} is dispatched to its own dissector`, match?.detector, payload.protocol);
}

// --- DTLS, which is found by content outside the list ----------------------------
// It keeps per-conversation state, so it is asked in udpTransport.ts before the
// list rather than from it - and must still reject every payload above, as
// every detector above must reject a DTLS record.
console.log();
const DTLS_RECORD = new Bytes().u8(22).u16(0xfefd).u16(0).u16(0, 0, 0).u16(12)
  .u8(1).u8(0, 0, 0).u16(0).u8(0, 0, 0).u8(0, 0, 0).build();
check('DTLS accepts its own record', looksLikeDtls(DTLS_RECORD, 0, DTLS_RECORD.length), true);
for (const payload of PAYLOADS) {
  check(`DTLS rejects ${payload.protocol}`, looksLikeDtls(payload.bytes, 0, payload.bytes.length), false);
}
check('no detector claims a DTLS record', detectUdpPayload(DTLS_RECORD, 0, DTLS_RECORD.length)?.detector ?? null, null);

// --- RTP, which is found per flow outside the list --------------------------------
// It is confirmed by a second datagram on its flow (`rtpStreams.ts`), so it is
// asked in udpTransport.ts after everything else - and its shape test must
// still reject every payload above, and the RTCP, STUN, DTLS and QUIC that
// share a WebRTC call's port with it (RFC 7983, RFC 5761).
console.log();
const RTP_PACKET = new Bytes().u8(0x90, 111).u16(4812).u32(96000, 0x5e2a01c4)
  .u16(0xbede, 1).u8(0x10, 0xaa, 0, 0).raw(new Array(40).fill(0x5c)).build();
check('RTP accepts its own packet', looksLikeRtp(RTP_PACKET, 0, RTP_PACKET.length), true);
const RTCP_PACKETS: { name: string; bytes: Uint8Array }[] = [
  { name: 'an RTCP Sender Report', bytes: new Bytes().u8(0x80, 200).u16(6).u32(1).zeros(20).build() },
  { name: 'an RTCP Receiver Report', bytes: new Bytes().u8(0x80, 201).u16(1).u32(1).build() },
  { name: 'an RTCP NACK', bytes: new Bytes().u8(0x81, 205).u16(3).u32(1, 2).u16(9, 0).build() },
  { name: 'an RTCP picture loss indication', bytes: new Bytes().u8(0x81, 206).u16(2).u32(1, 2).build() },
  { name: 'an RTCP extended report', bytes: new Bytes().u8(0x80, 207).u16(1).u32(1).build() },
  { name: 'a QUIC Initial', bytes: new Bytes().u8(0xc3).u32(1).u8(8).raw(new Array(60).fill(0x3c)).build() },
  { name: 'a QUIC short-header packet', bytes: new Bytes().u8(0x42, 0x48, 0x5c, 0x44, 0x40).raw(new Array(50).fill(0x9a)).build() },
  { name: 'a DTLS record', bytes: DTLS_RECORD },
];
for (const payload of [...PAYLOADS.map((p) => ({ name: p.protocol, bytes: p.bytes })), ...RTCP_PACKETS]) {
  check(`RTP rejects ${payload.name}`, looksLikeRtp(payload.bytes, 0, payload.bytes.length), false);
}
check('no detector claims an RTP packet', detectUdpPayload(RTP_PACKET, 0, RTP_PACKET.length)?.detector ?? null, null);

// --- payloads that are nothing --------------------------------------------------
console.log();
const NOT_PROTOCOLS: { name: string; bytes: Uint8Array }[] = [
  { name: 'an empty payload', bytes: new Bytes().build() },
  { name: 'three bytes', bytes: new Bytes().u8(1, 2, 3).build() },
  { name: 'all zeros', bytes: new Bytes().zeros(64).build() },
  { name: 'all 0xff', bytes: new Bytes().raw(new Array(64).fill(0xff)).build() },
  { name: 'plain English text', bytes: new Bytes().ascii('the quick brown fox jumps over').build() },
  // A QUIC short-header packet: fixed bit set, then a connection id. This is
  // 740 frames of the parity fixtures and must stay anonymous UDP, because
  // tshark cannot name it either without having seen the Initial.
  { name: 'a QUIC short-header packet',
    bytes: new Bytes().u8(0x42, 0x48, 0x5c, 0x44, 0x40).raw(new Array(50).fill(0x9a)).build() },
  // An HTTP request, which shares OPTIONS with SIP and colon-headers with all
  // the text protocols.
  { name: 'an HTTP request',
    bytes: new Bytes().ascii('OPTIONS / HTTP/1.1\r\nHost: example.com\r\n\r\n').build() },
  { name: 'a DNS query for example.com',
    bytes: new Bytes().u16(0x1234).u16(0x0100).u16(1, 0, 0, 0)
      .u8(7).ascii('example').u8(3).ascii('com').u8(0).u16(1, 1).build() },
];
for (const sample of NOT_PROTOCOLS) {
  check(`${sample.name} is claimed by nobody`,
    detectUdpPayload(sample.bytes, 0, sample.bytes.length)?.detector ?? null, null);
}

// --- the corpus: real UDP payloads nobody dispatched -----------------------------
//
// The hand-written negatives above are the cases I thought of. This is the
// ones I did not.
const FIXTURES = [
  'test/fixtures/inwire_capture_1788478187989.pcap',
  'test/fixtures/bulk_capture_1788426090876.pcap',
];

async function corpus(): Promise<void> {
  const present = FIXTURES.filter((f) => existsSync(f));
  if (present.length === 0) {
    console.log('\nSKIP  fixture corpus - captures not present (see test/fixtures/README.md)');
    return;
  }

  console.log();
  for (const path of present) {
    const { packets } = await PcapService.parseCaptureFile(
      new File([new Uint8Array(readFileSync(path))], 'f.pcap'), 1_000_000);

    // Frames this build already names are not the question - a detector never
    // sees them. The question is what it would do with the ones left over.
    const claimed = new Map<string, number>();
    let examined = 0;
    for (const packet of packets) {
      const protocols = packet.frameProtocols ?? [];
      if (!protocols.includes('udp')) continue;
      // Anonymous UDP: nothing above the transport claimed it.
      if (protocols[protocols.length - 1] !== 'udp') continue;
      if (packet.rawBytes.length === 0) continue;

      // The UDP payload starts 8 bytes past the transport header; recovering
      // the offset from the frame is not worth it here, so the whole frame is
      // offered from a plausible payload start. A detector that fires on a
      // sliding window of real traffic is exactly what this is looking for.
      const start = protocols.includes('ipv6') ? 62 : 42;
      if (packet.rawBytes.length <= start) continue;
      examined++;
      const match = detectUdpPayload(packet.rawBytes, start, packet.rawBytes.length);
      if (match) claimed.set(match.detector, (claimed.get(match.detector) ?? 0) + 1);
    }

    const name = path.split('/').pop()!.split('_')[0];
    // The reference's own RTP heuristic, switched on, finds no RTP in either
    // capture; neither may this build's flow test.
    const rtp = packets.filter((p) => (p.frameProtocols ?? []).includes('rtp')).map((p) => p.id);
    check(`${name}: no frame of it reads as RTP`, rtp.slice(0, 5), []);
    const total = [...claimed.values()].reduce((a, b) => a + b, 0);
    check(`${name}: no detector claims any of its ${examined} anonymous UDP payloads`,
      total === 0 ? [] : [...claimed.entries()].map(([d, n]) => `${d}=${n}`), []);
  }
}

corpus().then(() => {
  console.log();
  if (failures > 0) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All heuristic detector checks passed.');
  process.exit(0);
});
