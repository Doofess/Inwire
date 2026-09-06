/**
 * Assertion tests for the rest of Phase 6: IPv4 options, DSCP/ECN names, TTL
 * distance, IP fragments, ARP address conflicts, NTP, STUN and DNS over TCP.
 *
 *   npx tsx scripts/ipv4/options-and-fragments.ts
 *
 * Neither fixture contains a fragment, a STUN exchange, an NTP poll or a DNS
 * query over TCP, so the parity harness cannot see any of this. That is not a
 * reason to skip it - it is the reason this file exists. Every frame below is
 * built byte by byte and decoded through `decodeRawEthernetPacket`, the same
 * function live capture, pcap import and session restore all use.
 *
 * The fragment case is the one that was actually wrong rather than missing. A
 * non-first fragment carries application data where a transport header would
 * be, and it was being read as one - so the second fragment of a UDP datagram
 * was reported with two invented port numbers and a length taken out of the
 * payload. Nothing about that looks like a failure, which is what makes it
 * worth a test rather than a fix.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { L3Tracker } from '../../src/services/l3Tracker';
import { LINKTYPE } from '../../src/services/dissect/types';
import { dscpName, ecnName, inferTtl } from '../../src/services/dissectors/ipv4';
import { looksLikeNtp, looksLikeStun } from '../../src/services/dissectors/udpApps';
import type { Packet, ProtocolField } from '../../src/types/packet';

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
function checkTrue(name: string, condition: boolean) { check(name, condition, true); }

const MAC_DST = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAC_SRC = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

/** An Ethernet+IPv4 frame with whatever header fields and payload are asked for. */
function ipv4Frame(opts: {
  proto: number;
  payload: number[];
  options?: number[];
  tos?: number;
  ttl?: number;
  id?: number;
  moreFragments?: boolean;
  fragOffsetBytes?: number;
  src?: number[];
  dst?: number[];
}): Uint8Array {
  const options = opts.options ?? [];
  const ihl = 5 + options.length / 4;
  const total = ihl * 4 + opts.payload.length;
  const flagsAndOffset = ((opts.moreFragments ? 1 : 0) << 13) | ((opts.fragOffsetBytes ?? 0) / 8);
  const id = opts.id ?? 0x1234;
  return new Uint8Array([
    ...MAC_DST, ...MAC_SRC, 0x08, 0x00,
    0x40 | ihl, opts.tos ?? 0,
    (total >> 8) & 0xff, total & 0xff,
    (id >> 8) & 0xff, id & 0xff,
    (flagsAndOffset >> 8) & 0xff, flagsAndOffset & 0xff,
    opts.ttl ?? 64, opts.proto,
    0x00, 0x00,
    ...(opts.src ?? [10, 0, 0, 1]),
    ...(opts.dst ?? [10, 0, 0, 2]),
    ...options,
    ...opts.payload,
  ]);
}

let nextId = 1;
function decodeFull(frame: Uint8Array, tracker?: L3Tracker) {
  return decodeRawEthernetPacket(
    frame, nextId++, 1_700_000_000_000_000, 0, 0, frame.length,
    undefined, undefined, undefined, undefined, undefined, LINKTYPE.ETHERNET, tracker,
  );
}
function decode(frame: Uint8Array, tracker?: L3Tracker): Packet {
  return decodeFull(frame, tracker).packet;
}

function findField(fields: ProtocolField[], name: string): ProtocolField | undefined {
  for (const f of fields) {
    if (f.name === name) return f;
    if (f.children) {
      const hit = findField(f.children, name);
      if (hit) return hit;
    }
  }
  return undefined;
}

function ipLayer(packet: Packet) {
  return packet.layers.find((l) => l.name === 'Internet Protocol Version 4');
}

// --- DSCP, ECN and TTL ----------------------------------------------------------

check('DSCP 46 is expedited forwarding, not the number 46', dscpName(46), 'EF PHB');
check('DSCP 0 is CS0', dscpName(0), 'CS0');
check('DSCP 26 is AF31', dscpName(26), 'AF31');
check('an unassigned codepoint says so rather than guessing', dscpName(37), 'Unknown (37)');
check('the four ECN states are named', [0, 1, 2, 3].map(ecnName),
  ['Not-ECT', 'ECT(1)', 'ECT(0)', 'CE']);

check('a TTL of 57 is seven hops from a host that starts at 64', inferTtl(57), { initial: 64, hops: 7 });
check('...121 is seven hops from a Windows host', inferTtl(121), { initial: 128, hops: 7 });
check('...255 is a router one hop away, or on the wire', inferTtl(255), { initial: 255, hops: 0 });
check('...and 64 is the sender itself', inferTtl(64), { initial: 64, hops: 0 });
check('a TTL of 0 is not a distance', inferTtl(0), null);

{
  // 0xb8 = DSCP 46 (EF), ECN 0. Voice traffic marks itself this way, and the
  // whole reason to look is to see whether the marking survived the path.
  const packet = decode(ipv4Frame({ proto: 17, tos: 0xb8, ttl: 57, payload: [0, 53, 0, 53, 0, 8, 0, 0] }));
  const ds = findField(ipLayer(packet)!.fields, 'Differentiated Services Field');
  check('the DS field row names both halves', ds?.value, '0xb8 (DSCP: EF PHB, ECN: Not-ECT)');
  check('...and publishes them for filters', [packet.fields?.['ip.dsfield.dscp'], packet.fields?.['ip.dsfield.ecn']], [46, 0]);
  const ttl = findField(ipLayer(packet)!.fields, 'Time to Live (TTL)');
  check('the TTL row carries the distance it implies',
    ttl?.children?.map((c) => `${c.name}=${c.value}`),
    ['[Inferred initial TTL]=64', '[Hops away]=7']);
  checkTrue('...and both rows are marked as inferred, not read',
    (ttl?.children ?? []).every((c) => c.generated === true));
}

// --- IPv4 options ------------------------------------------------------------------

{
  // Router Alert: what every IGMP report on a normal network carries, and what
  // makes a router look inside a packet it would otherwise just forward.
  const packet = decode(ipv4Frame({
    proto: 2, ttl: 1,
    options: [0x94, 0x04, 0x00, 0x00],
    payload: [0x16, 0x00, 0x00, 0x00, 224, 0, 0, 22],
  }));
  const options = findField(ipLayer(packet)!.fields, 'Options');
  check('the option is read rather than skipped over', options?.children?.length, 1);
  check('...and named', options?.children?.[0].name, 'Router Alert (4 bytes)');
  check('...and what it asks for is spelled out',
    options?.children?.[0].value, 'Router shall examine packet');
  check('the transport header is still found past the options',
    packet.protocolLabel ?? packet.protocol, 'IGMPv2');
}

{
  // Record Route with two slots filled and one still empty: the pointer is
  // what separates the addresses that were written from the space left for
  // the ones that were not.
  const packet = decode(ipv4Frame({
    proto: 17, ttl: 64,
    options: [
      0x07, 0x0f, 0x0c,
      10, 0, 0, 1,
      10, 0, 0, 254,
      0, 0, 0, 0,
      0x00,
    ],
    payload: [0, 53, 0, 53, 0, 8, 0, 0],
  }));
  const options = findField(ipLayer(packet)!.fields, 'Options');
  check('Record Route lists the hops it collected',
    options?.children?.[0].value, '10.0.0.1, 10.0.0.254');
  check('...and shows the slot nobody has filled yet',
    options?.children?.[0].children?.filter((c) => c.name === 'Empty slot').length, 1);
  check('the End of Option List padding is listed too, not silently eaten',
    options?.children?.[1].name, 'End of Option List (EOL) (0)');
}

{
  // A length field that does not fit is a malformed packet, not permission to
  // read past the header.
  const packet = decode(ipv4Frame({
    proto: 17, options: [0x07, 0xfe, 0x00, 0x00], payload: [0, 53, 0, 53, 0, 8, 0, 0],
  }));
  const options = findField(ipLayer(packet)!.fields, 'Options');
  checkTrue('an option that overruns the header is reported, not read',
    String(options?.children?.[0].value).startsWith('Malformed'));
  checkTrue('...as an expert finding', options?.children?.[0].expertInfo?.category === 'Broken');
}

// --- fragments -----------------------------------------------------------------------

/** A DNS query for "example.com", as a UDP datagram body. */
const DNS_QUERY = [
  0xab, 0xcd, 0x01, 0x00,
  0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
  0x03, 0x63, 0x6f, 0x6d, 0x00,
  0x00, 0x01, 0x00, 0x01,
];

/** The same, wrapped in a UDP header - 8 + 29 = 37 bytes. */
const UDP_DATAGRAM = [
  0xc7, 0x38, 0x00, 0x35,
  0x00, 8 + DNS_QUERY.length,
  0x00, 0x00,
  ...DNS_QUERY,
];

{
  const tracker = new L3Tracker();
  // One UDP datagram in two fragments. The split is at 24 bytes because a
  // fragment offset counts in units of eight - and it lands mid-DNS-message,
  // so neither half parses on its own.
  const head = UDP_DATAGRAM.slice(0, 24);
  const tail = UDP_DATAGRAM.slice(24);

  const headFrame = nextId;
  const a = decode(ipv4Frame({ proto: 17, id: 0x4321, moreFragments: true, payload: head }), tracker);
  const completing = decodeFull(ipv4Frame({ proto: 17, id: 0x4321, fragOffsetBytes: 24, payload: tail }), tracker);
  const b = completing.packet;

  // Wireshark runs the transport dissector once, on the whole datagram, in the
  // frame that completed it. Every earlier fragment says what it is instead.
  check('the first fragment is a fragment, not half a UDP header',
    [a.protocolLabel, a.sourcePort], ['IPv4', undefined]);
  check('...and says so', a.info,
    'Fragmented IP protocol (proto=UDP 17, off=0, ID=4321)');

  check('the frame that completes the datagram carries the dissection',
    [b.sourcePort, b.destPort], [51000, 53]);
  check('...all the way up to the application layer', b.protocolLabel, 'DNS');
  checkTrue('...with the question that was split across two frames',
    b.info.includes('example.com'));
  check('...and the DNS layer really is in the tree',
    b.layers.some((l) => l.name === 'Domain Name System'), true);

  const reasm = findField(ipLayer(b)!.fields, '[2 Reassembled IPv4 fragments (37 bytes)]');
  check('the fragments that made it up are listed', reasm?.value,
    `#${headFrame}(24), #${headFrame + 1}(13)`);
  check('...each one a link to the frame it came from',
    reasm?.children?.map((c) => c.linkToFrame), [headFrame, headFrame + 1]);
  // The earlier fragment learns which frame finished the job the same way a
  // reassembled TLS record's segments do: as an InfoPatch the caller applies
  // over one pass of the buffer, not by reaching back into a packet here.
  check('the earlier fragment is told which frame finished the job',
    completing.infoPatches?.filter((p) => p.frameId === headFrame),
    [{ frameId: headFrame, suffix: ` [Reassembled in ${headFrame + 1}]` }]);

  // A row describing bytes that are not in this frame must not point the hex
  // view at this frame's offsets - the rule TLS reassembly already follows.
  const udp = b.layers.find((l) => l.name === 'User Datagram Protocol')!;
  checkTrue('the reassembled transport layer claims no bytes of this frame',
    udp.rawBytesRange === undefined && udp.fields.every((f) => f.rawBytesRange === undefined));
}

{
  // The middle fragment never arrived. A datagram with a hole in it is not a
  // datagram: handing the transport dissector a buffer with the gap quietly
  // zero-filled would produce a confident reading of bytes nobody sent.
  const tracker = new L3Tracker();
  decode(ipv4Frame({ proto: 17, id: 7, moreFragments: true, payload: UDP_DATAGRAM.slice(0, 8) }), tracker);
  const last = decode(ipv4Frame({ proto: 17, id: 7, fragOffsetBytes: 24, payload: UDP_DATAGRAM.slice(24) }), tracker);

  check('a datagram missing a fragment is not dissected', last.sourcePort, undefined);
  checkTrue('...and the gap is reported rather than filled in',
    String(findField(ipLayer(last)!.fields, '[Datagram incomplete]')?.value).includes('waiting for a missing fragment'));
  // A note, not a warning: at this frame there is no way to tell a fragment
  // that is late from one that will never arrive.
  check('...as a note, because a late fragment is normal',
    findField(ipLayer(last)!.fields, '[Datagram incomplete]')?.expertInfo?.category, 'CaptureGap');
}

{
  // Overlapping fragments are the classic evasion: a sender arranges for a
  // firewall and the host behind it to reassemble different datagrams out of
  // the same frames. Whichever rule a reassembler picks, the overlap itself
  // has to be visible.
  const tracker = new L3Tracker();
  const head = UDP_DATAGRAM.slice(0, 24);
  const tail = UDP_DATAGRAM.slice(24);
  decode(ipv4Frame({ proto: 17, id: 9, moreFragments: true, payload: head }), tracker);
  // A second copy of the first 8 bytes, with the ports changed.
  decode(ipv4Frame({
    proto: 17, id: 9, moreFragments: true,
    payload: [0xff, 0xff, 0xff, 0xff, 0x00, 37, 0x00, 0x00],
  }), tracker);
  const last = decode(ipv4Frame({ proto: 17, id: 9, fragOffsetBytes: 24, payload: tail }), tracker);

  check('the first copy of an overlapped byte is the one used',
    [last.sourcePort, last.destPort], [51000, 53]);
  // The duplicate contributed no bytes, so it is not listed as a contributor -
  // but the overlap it caused still is.
  const reasm = ipLayer(last)!.fields.find((f) => f.name.includes('Reassembled IPv4 fragments'));
  check('...and the duplicate is not counted as a contributor',
    reasm?.name, '[2 Reassembled IPv4 fragments (37 bytes)]');
  check('...but the overlap is reported', reasm?.expertInfo?.category, 'Broken');
  checkTrue('...saying which copy was kept',
    String(reasm?.expertInfo?.message).includes('first copy'));
}

{
  // Two datagrams between the same hosts, distinguished only by their
  // identification - which is what the field is for.
  const tracker = new L3Tracker();
  decode(ipv4Frame({ proto: 17, id: 1, moreFragments: true, payload: new Array(16).fill(0) }), tracker);
  const other = decode(ipv4Frame({ proto: 17, id: 2, fragOffsetBytes: 16, payload: new Array(8).fill(0) }), tracker);
  checkTrue('a fragment of a different datagram is not counted with the first',
    String(findField(ipLayer(other)!.fields, '[Datagram incomplete]')?.value).includes('8 captured'));
}

{
  // Out of order, which is the normal case on any path with more than one
  // route: the last fragment can arrive first, and it is the one that says how
  // long the datagram is.
  const tracker = new L3Tracker();
  const head = UDP_DATAGRAM.slice(0, 24);
  const tail = UDP_DATAGRAM.slice(24);
  const last = decode(ipv4Frame({ proto: 17, id: 0x5555, fragOffsetBytes: 24, payload: tail }), tracker);
  const first = decode(ipv4Frame({ proto: 17, id: 0x5555, moreFragments: true, payload: head }), tracker);

  check('a trailing fragment that arrives first cannot complete anything alone',
    last.sourcePort, undefined);
  check('...and the frame that fills the gap is the one that carries the dissection',
    [first.sourcePort, first.destPort], [51000, 53]);
}

{
  // Reassembly is what the tracker is for; without one, a fragment is still
  // not mistaken for a transport header.
  const lone = decode(ipv4Frame({
    proto: 17, id: 3, fragOffsetBytes: 16,
    payload: [0x1f, 0x90, 0x00, 0x50, 0xde, 0xad, 0xbe, 0xef],
  }));
  check('with no tracker a fragment is still not read as a UDP header',
    [lone.sourcePort, lone.destPort], [undefined, undefined]);
  checkTrue('...and specifically not as the ports its payload happens to contain',
    lone.sourcePort !== 8080 && lone.destPort !== 80);
}

{
  // The property that matters most, and the one the individual checks above
  // only approach: a datagram split any number of ways must dissect to what
  // the same datagram dissects to when it arrives whole. Anything less means
  // reassembly produces a *different* reading, which is worse than not
  // reassembling at all.
  const whole = decode(ipv4Frame({ proto: 17, payload: UDP_DATAGRAM }));

  for (const splits of [[8], [8, 16], [16, 24, 32], [8, 16, 24, 32]]) {
    const tracker = new L3Tracker();
    const bounds = [0, ...splits, UDP_DATAGRAM.length];
    let last: Packet | null = null;
    for (let i = 0; i < bounds.length - 1; i++) {
      last = decode(ipv4Frame({
        proto: 17, id: 0x7000 + splits.length,
        fragOffsetBytes: bounds[i],
        moreFragments: i < bounds.length - 2,
        payload: UDP_DATAGRAM.slice(bounds[i], bounds[i + 1]),
      }), tracker);
    }
    check(`split ${bounds.length - 1} ways, the datagram reads the same as when whole`,
      [last!.protocolLabel, last!.sourcePort, last!.destPort, last!.info],
      [whole.protocolLabel, whole.sourcePort, whole.destPort, whole.info]);
  }

  // ...including the tree, apart from the byte ranges a reassembled layer
  // deliberately does not claim.
  const tracker = new L3Tracker();
  decode(ipv4Frame({ proto: 17, id: 0x7777, moreFragments: true, payload: UDP_DATAGRAM.slice(0, 16) }), tracker);
  const done = decode(ipv4Frame({ proto: 17, id: 0x7777, fragOffsetBytes: 16, payload: UDP_DATAGRAM.slice(16) }), tracker);
  const names = (p: Packet) => p.layers
    .filter((l) => l.name !== 'Internet Protocol Version 4')
    .map((l) => l.name);
  check('...and the same layers are built above IP', names(done), names(whole));
  check('...with the same filterable fields for DNS',
    Object.keys(done.fields ?? {}).filter((k) => k.startsWith('dns.')).sort(),
    Object.keys(whole.fields ?? {}).filter((k) => k.startsWith('dns.')).sort());
}

// --- IPv6 fragments ----------------------------------------------------------------
// The same mechanism as IPv4's, keyed the way RFC 8200 4.5 keys it: source,
// destination and the Fragment header's 32-bit identification, with the payload
// protocol deliberately excluded - the Fragment header sits above whatever the
// payload turns out to be, which is why IPv6 moved fragmentation out of the
// fixed header in the first place.

const V6_SRC = [0x20, 0x01, 0x0d, 0xb8, ...new Array(11).fill(0), 0x01];
const V6_DST = [0x20, 0x01, 0x0d, 0xb8, ...new Array(11).fill(0), 0x02];

/** An Ethernet+IPv6 frame carrying a Fragment header and a slice of a datagram. */
function ipv6Fragment(opts: {
  ident: number;
  offsetBytes: number;
  moreFragments: boolean;
  payload: number[];
  nextHeader?: number;
}): Uint8Array {
  const offsetAndFlags = ((opts.offsetBytes / 8) << 3) | (opts.moreFragments ? 1 : 0);
  const frag = [
    opts.nextHeader ?? 17, 0x00,
    (offsetAndFlags >> 8) & 0xff, offsetAndFlags & 0xff,
    (opts.ident >>> 24) & 0xff, (opts.ident >>> 16) & 0xff,
    (opts.ident >>> 8) & 0xff, opts.ident & 0xff,
  ];
  const payloadLen = frag.length + opts.payload.length;
  return new Uint8Array([
    ...MAC_DST, ...MAC_SRC, 0x86, 0xdd,
    0x60, 0x00, 0x00, 0x00,
    (payloadLen >> 8) & 0xff, payloadLen & 0xff,
    44,          // Next Header: Fragment
    64,          // Hop Limit
    ...V6_SRC, ...V6_DST,
    ...frag,
    ...opts.payload,
  ]);
}

/** The same datagram with no Fragment header at all, for the equivalence check. */
function ipv6Whole(payload: number[], nextHeader = 17): Uint8Array {
  return new Uint8Array([
    ...MAC_DST, ...MAC_SRC, 0x86, 0xdd,
    0x60, 0x00, 0x00, 0x00,
    (payload.length >> 8) & 0xff, payload.length & 0xff,
    nextHeader, 64,
    ...V6_SRC, ...V6_DST,
    ...payload,
  ]);
}

function ipv6FragmentLayer(packet: Packet) {
  return packet.layers.find((l) => l.name === 'IPv6 Fragment');
}

{
  const tracker = new L3Tracker();
  const head = UDP_DATAGRAM.slice(0, 24);
  const tail = UDP_DATAGRAM.slice(24);
  const headFrame = nextId;

  const a = decode(ipv6Fragment({ ident: 0xdeadbeef, offsetBytes: 0, moreFragments: true, payload: head }), tracker);
  const completing = decodeFull(ipv6Fragment({ ident: 0xdeadbeef, offsetBytes: 24, moreFragments: false, payload: tail }), tracker);
  const b = completing.packet;

  check('the first IPv6 fragment is a fragment, not half a UDP header',
    [a.protocolLabel, a.sourcePort], ['IPv6', undefined]);
  checkTrue('...and names the datagram it belongs to',
    a.info.includes('ident=0xdeadbeef'));

  check('the frame that completes it carries the dissection',
    [b.sourcePort, b.destPort], [51000, 53]);
  check('...all the way up to the application layer', b.protocolLabel, 'DNS');
  checkTrue('...with the question that was split across two frames',
    b.info.includes('example.com'));

  const reasm = ipv6FragmentLayer(b)!.fields.find((f) => f.name.includes('Reassembled IPv6 fragments'));
  check('the fragments that made it up are listed', reasm?.value,
    `#${headFrame}(24), #${headFrame + 1}(13)`);
  check('...and hang off the Fragment header, which is what did the fragmenting',
    reasm?.name, '[2 Reassembled IPv6 fragments (37 bytes)]');
  check('the earlier fragment is told which frame finished the job',
    completing.infoPatches?.filter((p) => p.frameId === headFrame),
    [{ frameId: headFrame, suffix: ` [Reassembled in ${headFrame + 1}]` }]);

  const udp = b.layers.find((l) => l.name === 'User Datagram Protocol')!;
  checkTrue('the reassembled transport layer claims no bytes of this frame',
    udp.rawBytesRange === undefined && udp.fields.every((f) => f.rawBytesRange === undefined));
}

{
  // The identification is the key, and it is 32 bits wide - IPv4's is 16, and
  // a datagram whose id happens to collide in the low half is a different
  // datagram.
  const tracker = new L3Tracker();
  decode(ipv6Fragment({ ident: 0x00010000, offsetBytes: 0, moreFragments: true, payload: UDP_DATAGRAM.slice(0, 24) }), tracker);
  const other = decode(ipv6Fragment({ ident: 0x00020000, offsetBytes: 24, moreFragments: false, payload: UDP_DATAGRAM.slice(24) }), tracker);
  check('a fragment of a different datagram does not complete this one',
    other.sourcePort, undefined);
  checkTrue('...and says it is still waiting',
    String(ipv6FragmentLayer(other)!.fields.find((f) => f.name === '[Datagram incomplete]')?.value)
      .includes('waiting for a missing fragment'));
}

{
  // An atomic fragment - offset 0, More Fragments clear - is not fragmented at
  // all. RFC 6946 says to process it as an ordinary packet, and sending it
  // through the tracker would be a pointless round trip.
  const atomic = decode(ipv6Fragment({
    ident: 0x11112222, offsetBytes: 0, moreFragments: false, payload: UDP_DATAGRAM,
  }), new L3Tracker());
  check('an atomic fragment is dissected where it stands',
    [atomic.sourcePort, atomic.destPort, atomic.protocolLabel], [51000, 53, 'DNS']);
}

{
  // Out of order, which is the normal case: the trailing fragment can arrive
  // first, and the frame that fills the last hole is the one that carries the
  // dissection.
  const tracker = new L3Tracker();
  const last = decode(ipv6Fragment({ ident: 0x5150, offsetBytes: 24, moreFragments: false, payload: UDP_DATAGRAM.slice(24) }), tracker);
  const first = decode(ipv6Fragment({ ident: 0x5150, offsetBytes: 0, moreFragments: true, payload: UDP_DATAGRAM.slice(0, 24) }), tracker);
  check('a trailing IPv6 fragment that arrives first completes nothing alone',
    last.sourcePort, undefined);
  check('...and the frame that fills the gap carries the dissection',
    [first.sourcePort, first.destPort], [51000, 53]);
}

{
  // The property that matters most, as for IPv4: fragmented must read the same
  // as whole.
  const whole = decode(ipv6Whole(UDP_DATAGRAM));
  for (const splits of [[8], [8, 16], [8, 16, 24, 32]]) {
    const tracker = new L3Tracker();
    const bounds = [0, ...splits, UDP_DATAGRAM.length];
    let last: Packet | null = null;
    for (let i = 0; i < bounds.length - 1; i++) {
      last = decode(ipv6Fragment({
        ident: 0x9000 + splits.length,
        offsetBytes: bounds[i],
        moreFragments: i < bounds.length - 2,
        payload: UDP_DATAGRAM.slice(bounds[i], bounds[i + 1]),
      }), tracker);
    }
    check(`IPv6 split ${bounds.length - 1} ways reads the same as when whole`,
      [last!.protocolLabel, last!.sourcePort, last!.destPort, last!.info],
      [whole.protocolLabel, whole.sourcePort, whole.destPort, whole.info]);
  }
}

{
  // The fragmentable part may itself begin with extension headers: the walker
  // stops at the Fragment header, so anything after it belongs to the
  // reassembled datagram rather than to the frame that carried the first
  // fragment.
  const destOpts = [17, 0, 1, 4, 0, 0, 0, 0]; // Destination Options, 8 bytes, next = UDP
  const inner = [...destOpts, ...UDP_DATAGRAM];
  const tracker = new L3Tracker();
  decode(ipv6Fragment({ ident: 0xabcd, offsetBytes: 0, moreFragments: true, payload: inner.slice(0, 24), nextHeader: 60 }), tracker);
  const done = decode(ipv6Fragment({ ident: 0xabcd, offsetBytes: 24, moreFragments: false, payload: inner.slice(24), nextHeader: 60 }), tracker);

  check('an extension header inside the fragmentable part is walked after reassembly',
    done.layers.some((l) => l.name === 'IPv6 Destination Options'), true);
  check('...and the transport past it is still found',
    [done.sourcePort, done.destPort], [51000, 53]);
  checkTrue('...with its token in the layer chain',
    done.frameProtocols?.includes('ipv6.dstopts') === true);
}

// --- ARP: one address, two owners ------------------------------------------------------

{
  const tracker = new L3Tracker();
  const arp = (senderMac: number[], senderIp: number[]) => new Uint8Array([
    ...MAC_DST, ...senderMac, 0x08, 0x06,
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02,   // Ethernet/IPv4, reply
    ...senderMac, ...senderIp,
    ...MAC_DST, 10, 0, 0, 9,
  ]);

  const claim = decode(arp(MAC_SRC, [10, 0, 0, 7]), tracker);
  checkTrue('a first claim on an address is not a conflict',
    !claim.info.includes('duplicate'));

  const impostor = decode(arp([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01], [10, 0, 0, 7]), tracker);
  checkTrue('a second MAC claiming the same address is reported',
    impostor.info.includes('duplicate use of 10.0.0.7 detected!'));
  const row = findField(impostor.layers.find((l) => l.name.startsWith('Address Resolution'))!.fields,
    '[Duplicate IP address detected]');
  checkTrue('...with the frame that made the earlier claim, to jump to',
    row?.linkToFrame !== undefined);
  // Security rather than Broken: the frame decoded perfectly. What is wrong is
  // the network - two machines answering for one address, which is either a
  // misconfiguration or someone poisoning the segment.
  checkTrue('...and as a Security finding', row?.expertInfo?.category === 'Security');

  // A host really does change MAC - a failover, a new NIC, a laptop changing
  // docks - so the newest claim becomes the one to compare against. Reporting
  // it on every frame from then on would be noise, not a finding.
  const settled = decode(arp([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01], [10, 0, 0, 7]), tracker);
  checkTrue('the change is reported once, not on every frame after it',
    !settled.info.includes('duplicate'));
}

// --- NTP and STUN -----------------------------------------------------------------------

/** UDP over IPv4, with the ports asked for. */
function udpFrame(srcPort: number, dstPort: number, payload: number[]): Uint8Array {
  const len = 8 + payload.length;
  return ipv4Frame({
    proto: 17,
    payload: [
      (srcPort >> 8) & 0xff, srcPort & 0xff,
      (dstPort >> 8) & 0xff, dstPort & 0xff,
      (len >> 8) & 0xff, len & 0xff, 0x00, 0x00,
      ...payload,
    ],
  });
}

{
  // A client poll: LI 0, version 4, mode 3.
  const ntp = [0x23, 0x00, 0x06, 0xec, ...new Array(44).fill(0)];
  const packet = decode(udpFrame(51000, 123, ntp));
  check('an NTP poll is recognised', packet.protocolLabel, 'NTP');
  check('...and says which version and role', packet.info, 'NTP Version 4, client');
  check('...and appears in the layer chain', packet.frameProtocols?.includes('ntp'), true);
  check('...with its stratum published', packet.fields?.['ntp.stratum'], 0);

  checkTrue('48 bytes with a sane mode and stratum looks like NTP',
    looksLikeNtp(new Uint8Array(ntp), 0, 48));
  checkTrue('...but 48 bytes of anything does not',
    !looksLikeNtp(new Uint8Array([0xff, 0xff, ...new Array(46).fill(0xff)]), 0, 48));
  checkTrue('...and neither does a message of the wrong length',
    !looksLikeNtp(new Uint8Array(ntp), 0, 40));
}

{
  // A STUN Binding Request with a SOFTWARE attribute, on an arbitrary port -
  // which is where ICE actually puts it.
  const software = [0x80, 0x22, 0x00, 0x04, 0x74, 0x65, 0x73, 0x74];
  const stun = [
    0x00, 0x01, 0x00, software.length,
    0x21, 0x12, 0xa4, 0x42,
    ...Array.from({ length: 12 }, (_, i) => i + 1),
    ...software,
  ];
  const packet = decode(udpFrame(54321, 61234, stun));
  check('STUN is found on a port nothing would have guessed', packet.protocolLabel, 'STUN');
  check('...and its message named', packet.info, 'Binding Request');
  check('...and it joins the layer chain', packet.frameProtocols?.includes('stun'), true);

  checkTrue('the magic cookie is what makes that safe', looksLikeStun(new Uint8Array(stun), 0, stun.length));
  const noCookie = [...stun];
  noCookie[4] = 0x00;
  checkTrue('...and without it nothing is claimed',
    !looksLikeStun(new Uint8Array(noCookie), 0, noCookie.length));
}

{
  // XOR-MAPPED-ADDRESS exists so that a NAT rewriting payloads by pattern
  // cannot silently corrupt the address inside. Unmasking it is the point of
  // reading it at all.
  // Port 50000 (0xc350) XORed with the cookie's top half (0x2112) is 0xe242;
  // 203.0.113.5 XORed byte-wise with the whole cookie is ea:12:d5:47.
  const attr = [
    0x00, 0x20, 0x00, 0x08,           // XOR-MAPPED-ADDRESS, 8 bytes
    0x00, 0x01,                       // reserved, family IPv4
    0xc3 ^ 0x21, 0x50 ^ 0x12,         // X-Port
    203 ^ 0x21, 0 ^ 0x12, 113 ^ 0xa4, 5 ^ 0x42,
  ];
  const stun = [
    0x01, 0x01, 0x00, attr.length,
    0x21, 0x12, 0xa4, 0x42,
    ...Array.from({ length: 12 }, (_, i) => i + 1),
    ...attr,
  ];
  const packet = decode(udpFrame(3478, 51000, stun));
  check('a Success Response is named as one', packet.info, 'Binding Success Response');
  const mapped = findField(
    packet.layers.find((l) => l.name.startsWith('Session Traversal'))!.fields,
    'XOR-MAPPED-ADDRESS');
  check('...and the address it discovered is unmasked', mapped?.value, '203.0.113.5:50000');
}

// --- DNS over TCP -------------------------------------------------------------------------

{
  // The same wire format as the datagram form, behind a two-byte length. A
  // zone transfer and every response too big for a datagram arrive this way,
  // and the dispatch only ever looked at UDP.
  const query = [
    0xab, 0xcd, 0x01, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
    0x03, 0x63, 0x6f, 0x6d, 0x00,                   // "com"
    0x00, 0x01, 0x00, 0x01,                         // A, IN
  ];
  const tcp = [
    0xc7, 0x38, 0x00, 0x35,
    0x00, 0x00, 0x03, 0xe8,
    0x00, 0x00, 0x00, 0x00,
    0x50, 0x18, 0x20, 0x00,
    0x00, 0x00, 0x00, 0x00,
    (query.length >> 8) & 0xff, query.length & 0xff,
    ...query,
  ];
  const packet = decode(ipv4Frame({ proto: 6, payload: tcp }));
  check('DNS over TCP is dissected, not left as a TCP segment', packet.protocolLabel, 'DNS');
  checkTrue('...with the question in the Info column', packet.info.includes('example.com'));
  check('...and a DNS layer in the tree',
    packet.layers.some((l) => l.name === 'Domain Name System'), true);

  // A message the segment does not contain in full needs the reassembly TLS
  // gets, and claiming it here would mean parsing half a message and
  // reporting the half.
  const split = [...tcp];
  split[20] = 0xff;
  const partial = decode(ipv4Frame({ proto: 6, payload: split }));
  checkTrue('a message split across segments is not half-parsed',
    partial.protocolLabel !== 'DNS');
}

// --- segmentation offload -------------------------------------------------------------------

{
  const frame = ipv4Frame({ proto: 6, payload: new Array(60).fill(0) });
  const big = decodeRawEthernetPacket(
    frame, nextId++, 1_700_000_000_000_000, 0, 0, 9000,
    undefined, undefined, undefined, undefined, undefined, LINKTYPE.ETHERNET,
  ).packet;
  const note = findField(big.layers[0].fields, '[Frame exceeds MTU]');
  checkTrue('a frame past the MTU is explained rather than left to look like damage',
    note !== undefined);
  check('...as unverifiable, since it is our own send path rather than the wire', note?.expertInfo?.category, 'Unverifiable');

  const normal = decode(frame);
  check('a normal frame gets no such note',
    findField(normal.layers[0].fields, '[Frame exceeds MTU]'), undefined);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All IPv4 option, fragment, ARP, NTP, STUN and DNS-over-TCP checks passed.');
process.exit(0);
