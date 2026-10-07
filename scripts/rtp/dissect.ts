/**
 * RTP against the reference, row for row.
 *
 *   npx tsx scripts/rtp/dissect.ts
 *
 * A laptop on a call carries RTP - WebRTC's SRTP keeps the RTP header in the
 * clear - and neither fixture holds a single packet of it. So the streams are
 * built here from RFC 3550 and RFC 8285: every static payload type the
 * reference names, contributing sources, padding, one- and two-byte header
 * extensions and an unknown profile's words, sequence and timestamp wrap,
 * two SSRCs sharing a flow, RFC 4733 telephone events, and the datagrams that
 * are shaped almost like RTP and must stay UDP.
 *
 * The reference reads RTP without signalling only with its `rtp_udp`
 * heuristic switched on, so that is how it is asked here. Its heuristic
 * claims a flow on the first datagram; this build waits for a second that
 * agrees (`rtpStreams.ts`). Each stream's first datagram is therefore in the
 * capture - the reference's setup frame and extended numbers count it - but
 * not compared, and its reading here is asserted instead: plain UDP.
 */
import { udpFrameTo } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';

interface RtpOptions {
  pt: number;
  seq: number;
  ts?: number;
  ssrc?: number;
  marker?: boolean;
  csrc?: number[];
  /** The extension header whole: profile, length in words, then the words. */
  ext?: number[];
  payload?: number[];
  /** Bytes of padding, the count byte included. */
  pad?: number;
  version?: number;
}
const be32 = (n: number) => [(n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
function rtp(o: RtpOptions): number[] {
  const csrc = o.csrc ?? [];
  const first = ((o.version ?? 2) << 6) | (o.pad !== undefined ? 0x20 : 0) | (o.ext !== undefined ? 0x10 : 0) | csrc.length;
  return [
    first, (o.marker ? 0x80 : 0) | o.pt, (o.seq >> 8) & 255, o.seq & 255, ...be32(o.ts ?? 160 * o.seq), ...be32(o.ssrc ?? 0x5e2a01c4),
    ...csrc.flatMap(be32), ...(o.ext ?? []), ...(o.payload ?? [0xd5, 0xd4, 0xd7, 0xd6]),
    ...(o.pad !== undefined ? [...Array(o.pad - 1).fill(0), o.pad] : []),
  ];
}

const LAPTOP = '192.168.1.20';
const PEER = '203.0.113.7';
let flowPort = 50000;
/** A new flow: its own source and destination port pair, so its numbers start afresh. */
function flow() {
  const src = flowPort, dst = flowPort + 1000;
  flowPort += 2;
  return (bytes: number[]) => udpFrameTo(LAPTOP, PEER, src, dst, Uint8Array.from(bytes));
}
const FIRST = 'the first datagram of a flow: the reference claims it, this build waits for the second';

// --- one call's audio, and everything a header can carry -----------------------
const audio = flow();
const ONE_BYTE = [0xbe, 0xde, 0, 2, 0x10, 0xaa, 0x21, 0xbb, 0xcc, 0, 0, 0];
const cases: OracleCase[] = [
  { label: 'G.711 audio, first', frame: audio(rtp({ pt: 0, seq: 1 })), notCompared: FIRST },
  { label: 'G.711 audio', frame: audio(rtp({ pt: 0, seq: 2, payload: Array(160).fill(0xff) })) },
  { label: 'a talkspurt start', frame: audio(rtp({ pt: 0, seq: 3, marker: true })) },
  { label: 'two contributing sources', frame: audio(rtp({ pt: 8, seq: 4, csrc: [1, 0xdeadbeef] })) },
  { label: 'padding', frame: audio(rtp({ pt: 8, seq: 5, pad: 3 })) },
  { label: 'one byte of padding', frame: audio(rtp({ pt: 8, seq: 6, pad: 1 })) },
  { label: 'padding and nothing else', frame: audio(rtp({ pt: 8, seq: 7, payload: [], pad: 4 })) },
  { label: 'RFC 8285 one-byte extensions', frame: audio(rtp({ pt: 111, seq: 8, ext: ONE_BYTE })) },
  {
    label: 'one-byte extensions with padding between, and the reserved 15',
    frame: audio(rtp({ pt: 111, seq: 9, ext: [0xbe, 0xde, 0, 2, 0x10, 0xaa, 0, 0, 0xf0, 1, 2, 3] })),
  },
  {
    label: 'a sixteen-byte one-byte extension',
    frame: audio(rtp({ pt: 111, seq: 10, ext: [0xbe, 0xde, 0, 5, 0x3f, ...Array(16).fill(7), 0, 0, 0] })),
  },
  {
    label: 'RFC 8285 two-byte extensions, with application bits',
    frame: audio(rtp({ pt: 111, seq: 11, ext: [0x10, 0x05, 0, 3, 0, 0, 1, 1, 0xaa, 2, 0, 3, 3, 1, 2, 3, 0] })),
  },
  { label: 'an extension no profile describes', frame: audio(rtp({ pt: 111, seq: 12, ext: [0x12, 0x34, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8] })) },
  { label: 'an empty extension', frame: audio(rtp({ pt: 111, seq: 13, ext: [0x12, 0x34, 0, 0] })) },
  {
    label: 'sources, an extension and padding together',
    frame: audio(rtp({ pt: 0, seq: 14, csrc: [9], ext: [0xbe, 0xde, 0, 1, 0x20, 1, 2, 3], payload: [5, 6], pad: 2 })),
  },
  { label: 'a bare header', frame: audio(rtp({ pt: 0, seq: 15, payload: [] })) },
  { label: 'a second SSRC on the same flow', frame: audio(rtp({ pt: 13, seq: 500, ts: 7000, ssrc: 0x11 })) },
  { label: 'version 1 on an RTP flow', frame: audio(rtp({ pt: 0, seq: 16, version: 1 })) },
  { label: 'payload type 72 on an RTP flow', frame: audio(rtp({ pt: 72, seq: 17 })) },
  { label: 'a padding count past the payload', frame: audio([...rtp({ pt: 0, seq: 18, payload: [1, 2] }), 9].map((b, i) => (i === 0 ? b | 0x20 : b))) },
  { label: 'a zero padding count', frame: audio([...rtp({ pt: 0, seq: 19, payload: [1, 2] }), 0].map((b, i) => (i === 0 ? b | 0x20 : b))) },
  { label: 'contributing sources past the end', frame: audio(rtp({ pt: 0, seq: 20, csrc: [1, 2, 3], payload: [] }).slice(0, 20)) },
  { label: 'an extension past the end', frame: audio(rtp({ pt: 0, seq: 21, ext: [0xbe, 0xde, 0, 5, 0x10, 0xaa], payload: [] })) },
  { label: 'eleven bytes', frame: audio(rtp({ pt: 0, seq: 22 }).slice(0, 11)) },
  { label: 'audio again after all that', frame: audio(rtp({ pt: 0, seq: 23 })) },
];

// --- sequence and timestamp wrap, as the reference unwraps them ----------------
const wrap = flow();
cases.push(
  { label: 'near the top of the sequence space, first', frame: wrap(rtp({ pt: 0, seq: 65534, ts: 4294967000 })), notCompared: FIRST },
  { label: 'the last sequence number', frame: wrap(rtp({ pt: 0, seq: 65535, ts: 4294967200 })) },
  { label: 'the sequence and timestamp wrap', frame: wrap(rtp({ pt: 0, seq: 0, ts: 100 })) },
  { label: 'a late packet from before the wrap', frame: wrap(rtp({ pt: 0, seq: 65535, ts: 4294967200 })) },
  { label: 'after the wrap', frame: wrap(rtp({ pt: 0, seq: 1, ts: 300 })) },
);

// --- every payload type the reference names, on one flow -----------------------
// Not 72-76, which are refused; not 99, 100 and 101, which the reference hands
// to RFC 2198 and RFC 4733; not the five static types with a codec dissector
// of their own (4, 26, 31, 32, 34), whose Protocol column is the codec's; and
// not 33, MPEG-2 transport, whose payload the reference hands to its MP2T
// dissector and then draws no row for.
const names = flow();
const NAMED = Array.from({ length: 128 }, (_, pt) => pt)
  .filter((pt) => !(pt >= 72 && pt <= 76) && ![4, 26, 31, 32, 33, 34, 99, 100, 101].includes(pt));
cases.push({ label: 'payload type 0, first', frame: names(rtp({ pt: 0, seq: 1000, ssrc: 0x1 })), notCompared: FIRST });
NAMED.forEach((pt, i) => cases.push({ label: `payload type ${pt}`, frame: names(rtp({ pt, seq: 1001 + i, ssrc: 0x1 })) }));

// --- telephone events: a key pressed during a call ------------------------------
const dtmf = flow();
const event = (id: number, flags: number, duration: number) => [id, flags, (duration >> 8) & 255, duration & 255];
cases.push(
  { label: 'audio before a key press, first', frame: dtmf(rtp({ pt: 0, seq: 1 })), notCompared: FIRST },
  { label: 'DTMF 5 pressed', frame: dtmf(rtp({ pt: 101, seq: 2, marker: true, payload: event(5, 0x0a, 160) })) },
  { label: 'DTMF 5 released', frame: dtmf(rtp({ pt: 101, seq: 3, payload: event(5, 0x8a, 320) })) },
  { label: 'two events, of which the reference reads one', frame: dtmf(rtp({ pt: 101, seq: 4, payload: [...event(11, 0x0a, 160), ...event(16, 0x8a, 800)] })) },
  { label: 'an event nobody names', frame: dtmf(rtp({ pt: 101, seq: 5, payload: event(17, 0x0a, 160) })) },
  { label: 'an event with its reserved bit set', frame: dtmf(rtp({ pt: 101, seq: 6, payload: event(255, 0xca, 160) })) },
  { label: 'an event with padding', frame: dtmf(rtp({ pt: 101, seq: 7, payload: event(1, 0x0a, 160), pad: 2 })) },
  { label: 'an event with a trailing byte', frame: dtmf(rtp({ pt: 101, seq: 8, payload: [...event(1, 0x0a, 160), 9] })) },
  { label: 'an event packet with no event', frame: dtmf(rtp({ pt: 101, seq: 9, payload: [] })) },
  { label: "Cisco's NSE on payload type 100", frame: dtmf(rtp({ pt: 100, seq: 10, payload: event(200, 0x0a, 160) })) },
);

// --- WebRTC: STUN, DTLS, RTP and RTCP on one port pair ---------------------------
// RFC 7983's demultiplexing by first byte, and RFC 5761's RTCP beside RTP.
const webrtc = flow();
const stunBinding = [0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, ...Array(12).fill(0x11)];
const senderReport = [0x80, 200, 0, 6, ...be32(0x5e2a01c4), ...Array(20).fill(0)];
const nack = [0x81, 205, 0, 3, ...be32(0x5e2a01c4), ...be32(0x77), 0, 9, 0, 0];
cases.push(
  { label: 'WebRTC: a connectivity check', frame: webrtc(stunBinding) },
  { label: 'WebRTC: media, first', frame: webrtc(rtp({ pt: 111, seq: 40, ext: ONE_BYTE })), notCompared: FIRST },
  { label: 'WebRTC: media', frame: webrtc(rtp({ pt: 111, seq: 41, ext: ONE_BYTE })) },
  { label: 'WebRTC: a connectivity check mid-call', frame: webrtc(stunBinding) },
  { label: 'WebRTC: a sender report on the media port', frame: webrtc(senderReport) },
  { label: 'WebRTC: a NACK on the media port', frame: webrtc(nack) },
  { label: 'WebRTC: media again', frame: webrtc(rtp({ pt: 111, seq: 42, ext: ONE_BYTE })) },
);

// --- a flow whose second datagram does not agree --------------------------------
// Random bytes under the version bits: the reference's heuristic reads all
// three as RTP; this build reads none of them, because no two share an SSRC.
const noise = flow();
const NOISE = 'shaped like RTP but no two agree: the reference\'s heuristic claims it, this build does not';
const noiseFrames = [0x91a2b3c4, 0x0badf00d, 0x77777777].map((ssrc, i) => noise(rtp({ pt: 33 + i, seq: 7 * i + 3, ssrc, payload: [ssrc & 255, i] })));
noiseFrames.forEach((frame, i) => cases.push({ label: `unrelated datagram ${i + 1}`, frame, notCompared: NOISE }));

const packets = await compareWithReference(cases, { rows: /^rtp(event)?\./, tsharkArgs: ['--enable-heuristic', 'rtp_udp'] });
await checkRevisit(cases);

const at = (label: string) => packets[cases.findIndex((c) => c.label === label)];
for (const [i, c] of cases.entries()) {
  if (c.notCompared === undefined) continue;
  check(`${c.label}: plain UDP here`, packets[i]?.protocol === 'UDP' && packets[i]?.protocolLabel === undefined
    && !(packets[i]?.frameProtocols ?? []).includes('rtp'), `${packets[i]?.protocolLabel} ${packets[i]?.frameProtocols?.join(':')}`);
}
const audioPacket = at('G.711 audio');
check('audio is the `rtp` layer over UDP', audioPacket?.frameProtocols?.slice(-2).join(':') === 'udp:rtp', audioPacket?.frameProtocols?.join(':'));
check('the SSRC is a field', audioPacket?.fields?.['rtp.ssrc'] === 0x5e2a01c4);
check('the payload type is a field', at('two contributing sources')?.fields?.['rtp.p_type'] === 8);
check('the extended sequence number counts the wrap', at('after the wrap')?.fields?.['rtp.extseq'] === 65537);
const press = at('DTMF 5 pressed');
check('a key press is `rtp:rtpevent`', press?.frameProtocols?.slice(-2).join(':') === 'rtp:rtpevent', press?.frameProtocols?.join(':'));
check('...and its digit is a field', press?.fields?.['rtpevent.event_id'] === 5);
const setup = audioPacket?.layers.find((l) => l.name === 'Real-Time Transport Protocol')?.fields[0]?.children?.[0];
check('the setup frame links to the flow\'s first datagram', setup?.linkToFrame === 1, JSON.stringify(setup));
finish('rtp');
