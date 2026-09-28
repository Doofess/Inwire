/**
 * ICMP, and the datagram an error quotes back.
 *
 *   npx tsx scripts/icmp/dissect.ts
 *
 * **Neither fixture holds a single ICMP error frame.** Both captures were
 * taken on a working link, so between them they contain 528 echo requests and
 * replies, 24 Neighbor Discovery messages and five MLDv2 reports - and not one
 * Destination Unreachable, Time Exceeded, Redirect or Packet Too Big. So
 * `scripts/parity/tree-coverage.ts` can measure the echo half to the last
 * field and can say nothing at all about the half that matters most when
 * somebody opens a capture: the router explaining why a packet did not arrive.
 *
 * That is what this file is for, and the move is the one
 * `scripts/parity/synthetic.ts` already makes for protocols the captures do
 * not contain - frames built byte by byte from the RFC, written to a real
 * `.pcap`, dissected by the real parser. The frame builders are imported from
 * there rather than copied, so an error frame here is an ordinary IPv4 frame
 * with an ICMP payload and nothing about it is special-cased.
 *
 * **The embedded packet is also invisible to the coverage tool by
 * construction**, which is the second reason this exists. That tool is
 * first-occurrence-wins per frame, so a quoted `ip.src` collides with the
 * outer one and the recursion could be deleted entirely without moving a
 * single number. The assertions below name the layers.
 */
import { useRepositoryWiresharkProfile } from '../wiresharkProfile';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { Bytes, internetChecksum, ipv4, pcapOf, tcp, udp } from '../parity/synthetic';
import { PcapService } from '../../src/services/pcapParser';
import { fieldValue } from '../../src/services/dissect/fieldAccess';
import type { Packet, ProtocolField } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

// --- building the frames -----------------------------------------------------

/**
 * Two MACs rather than `synthetic.ts`'s pair, and the reason is the checksum.
 *
 * `inferHostFromFrames` decides who took the capture before anything is
 * dissected for real, and `checksumVerdict` reads that answer: a frame this
 * machine SENT was handed to the sniffer before the NIC filled its checksum
 * in, so the honest verdict is `Unverified` rather than a verdict at all.
 * `synthetic.ts` puts the same source MAC on every frame, which makes every
 * frame look outbound and every checksum unverifiable - fine for a harness
 * comparing Info columns, useless for asserting that a correct checksum reads
 * as correct.
 *
 * So the host has a MAC and the far side has another, and the frames below
 * travel in the direction their message actually travels.
 */
const HOST_MAC = '00:00:5e:00:53:01';
const PEER_MAC = '00:00:5e:00:53:02';

function ethernetTo(etherType: number, toHost: boolean): Bytes {
  return new Bytes()
    .mac(toHost ? HOST_MAC : PEER_MAC)
    .mac(toHost ? PEER_MAC : HOST_MAC)
    .u16(etherType);
}

/**
 * An ICMP message with a correct checksum, wrapped in IPv4 and Ethernet.
 *
 * The checksum is computed rather than zeroed for the reason `ipv4` gives
 * about its own: `checksumVerdict` reads it, and a frame that fails its own
 * check would be exercising the offload policy instead of the dissector.
 */
function icmpFrame(body: Uint8Array, toHost = true, src = '192.0.2.9', dst = '192.0.2.1'): Uint8Array {
  const message = Uint8Array.from(body);
  const sum = internetChecksum(message);
  message[2] = (sum >> 8) & 0xff;
  message[3] = sum & 0xff;
  return Uint8Array.from([...ethernetTo(0x0800, toHost).build(), ...ipv4(1, message, src, dst)]);
}

/** An echo request or reply: type, code 0, checksum, id, sequence, payload. */
function echo(type: number, id: number, seq: number, payload: string): Uint8Array {
  const outbound = type === 8;
  return icmpFrame(new Bytes().u8(type, 0).u16(0, id, seq).ascii(payload).build(),
    !outbound,
    outbound ? '192.0.2.1' : '192.0.2.9',
    outbound ? '192.0.2.9' : '192.0.2.1');
}

/**
 * An ICMP error: four bytes after the code, then the quote.
 *
 * RFC 792 says the quote is the original IP header **plus the first 64 bits**
 * of what followed it, and that is exactly what is written here - eight bytes,
 * not the whole datagram. Getting that right in the fixture is the point: a
 * dissector handed the entire original packet would pass a test that a real
 * router's message fails.
 */
function icmpError(type: number, code: number, afterCode: Bytes, quoted: Uint8Array): Uint8Array {
  const ipHeaderLength = (quoted[0] & 0x0f) * 4;
  return icmpFrame(new Bytes()
    .u8(type, code).u16(0)
    .raw(afterCode.build())
    .raw(quoted.subarray(0, ipHeaderLength + 8))
    .build());
}

/** An IPv6 header wrapping `payload`, with the next-header byte given. */
function ipv6(nextHeader: number, payload: Uint8Array, src: string, dst: string): Uint8Array {
  const address = (text: string) => text.split(':').flatMap((group) => {
    const value = parseInt(group, 16);
    return [(value >> 8) & 0xff, value & 0xff];
  });
  return Uint8Array.from([
    ...new Bytes().u32(0x60000000).u16(payload.length).u8(nextHeader, 64)
      .raw(address(src)).raw(address(dst)).build(),
    ...payload,
  ]);
}

const V6_SRC = '2001:0db8:0000:0000:0000:0000:0000:0009';
const V6_DST = '2001:0db8:0000:0000:0000:0000:0000:0001';

/** An ICMPv6 message, checksummed over the RFC 8200 pseudo-header. */
function icmpv6Frame(body: Uint8Array): Uint8Array {
  const message = Uint8Array.from(body);
  const address = (text: string) => text.split(':').flatMap((group) => {
    const value = parseInt(group, 16);
    return [(value >> 8) & 0xff, value & 0xff];
  });
  const pseudo = new Bytes()
    .raw(address(V6_SRC)).raw(address(V6_DST))
    .u32(message.length).u8(0, 0, 0, 58)
    .build();
  const sum = internetChecksum([...pseudo, ...message]);
  message[2] = (sum >> 8) & 0xff;
  message[3] = sum & 0xff;
  return Uint8Array.from([
    ...ethernetTo(0x86dd, true).build(), ...ipv6(58, message, V6_SRC, V6_DST),
  ]);
}

/** The datagram every error below is about: a DNS query that went nowhere. */
const ORIGINAL_UDP = ipv4(17, udp(51234, 53, new Uint8Array(20)), '192.0.2.1', '198.51.100.1');
/** And one that is TCP, whose header does NOT fit in eight quoted bytes. */
const ORIGINAL_TCP = ipv4(6, tcp(44444, 443, 1000, 2000, new Uint8Array(100)), '192.0.2.1', '198.51.100.1');
const ORIGINAL_V6_TCP = ipv6(6, tcp(44444, 443, 1000, 2000, new Uint8Array(100)), V6_DST, '2001:0db8:0000:0000:0000:0000:0000:00ff');

const FRAMES: { name: string; bytes: Uint8Array }[] = [
  { name: 'echo request', bytes: echo(8, 0x1234, 7, 'abcdefgh') },
  { name: 'echo reply', bytes: echo(0, 0x1234, 7, 'abcdefgh') },
  { name: 'port unreachable', bytes: icmpError(3, 3, new Bytes().zeros(4), ORIGINAL_UDP) },
  // Two unused bytes and then the MTU, which is the whole point of the message.
  { name: 'fragmentation needed', bytes: icmpError(3, 4, new Bytes().u16(0, 1400), ORIGINAL_TCP) },
  { name: 'time exceeded', bytes: icmpError(11, 0, new Bytes().zeros(4), ORIGINAL_UDP) },
  { name: 'redirect', bytes: icmpError(5, 1, new Bytes().ipv4('192.0.2.254'), ORIGINAL_UDP) },
  { name: 'parameter problem', bytes: icmpError(12, 0, new Bytes().u8(20).zeros(3), ORIGINAL_UDP) },
  {
    name: 'packet too big',
    bytes: icmpv6Frame(new Bytes().u8(2, 0).u16(0).u32(1280)
      .raw(ORIGINAL_V6_TCP.subarray(0, 40 + 8)).build()),
  },
];

// --- dissecting them ---------------------------------------------------------

const directory = mkdtempSync(join(tmpdir(), 'inwire-icmp-'));
const capture = join(directory, 'icmp.pcap');
writeFileSync(capture, pcapOf(FRAMES.map((f) => f.bytes)));

const { packets } = await PcapService.parseCaptureFile(
  new File([readFileSync(capture)], 'icmp.pcap'), Number.POSITIVE_INFINITY, true);

check('every synthetic frame dissected', packets.length, FRAMES.length);

/** Every row in a frame's tree, depth first, with its abbrev. */
function rows(packet: Packet): ProtocolField[] {
  const out: ProtocolField[] = [];
  const visit = (fields: ProtocolField[]) => {
    for (const field of fields) {
      out.push(field);
      if (field.children) visit(field.children);
    }
  };
  for (const layer of packet.layers ?? []) visit(layer.fields);
  return out;
}

const valueOf = (packet: Packet, abbrev: string): unknown =>
  rows(packet).find((row) => row.abbrev === abbrev)?.value;
const allValuesOf = (packet: Packet, abbrev: string): unknown[] =>
  rows(packet).filter((row) => row.abbrev === abbrev).map((row) => row.value);
const layerNames = (packet: Packet): string[] => (packet.layers ?? []).map((l) => l.name);

const at = (name: string): Packet => {
  const index = FRAMES.findIndex((f) => f.name === name);
  return packets[index];
};

// --- the echo half, which the fixtures also cover ----------------------------

console.log('\n--- echo ---');
{
  const request = at('echo request');
  // The reference draws the same sixteen bits twice, because most ping
  // implementations count in host order: 0x1234 read the other way is 0x3412.
  check('identifier, big-endian', valueOf(request, 'icmp.ident'), '4660 (0x1234)');
  check('identifier, little-endian', valueOf(request, 'icmp.ident_le'), '13330 (0x3412)');
  check('sequence, big-endian', valueOf(request, 'icmp.seq'), '7 (0x0007)');
  check('sequence, little-endian', valueOf(request, 'icmp.seq_le'), '1792 (0x0700)');
  check('the payload after the echo header', valueOf(request, 'icmp.data'),
    '61:62:63:64:65:66:67:68');
  check('a computed checksum verifies', valueOf(request, 'icmp.checksum.status'), 'Good');

  const reply = at('echo reply');
  check('the reply names the request frame', valueOf(reply, 'icmp.resp_to'), 1);
  // `pcapOf` stamps consecutive frames one second apart, so the round trip is
  // exactly 1,000 ms and the assertion is on an exact string rather than a
  // tolerance.
  check('...and how long the round trip took', valueOf(reply, 'icmp.resptime'), '1000.000 ms');
  check('a request carries neither', [valueOf(request, 'icmp.resp_to'), valueOf(request, 'icmp.resptime')],
    [undefined, undefined]);
}

// --- the quoted datagram -----------------------------------------------------

console.log('\n--- the datagram the error is about ---');
{
  const unreachable = at('port unreachable');
  // The quote is a whole IPv4 header and a whole UDP header, so both dissect
  // and both appear UNDER the ICMP layer rather than replacing anything above
  // it. This is the assertion the coverage tool structurally cannot make.
  check('the quoted IPv4 and UDP headers become layers of their own',
    layerNames(unreachable),
    ['Frame', 'Ethernet II', 'Internet Protocol Version 4', 'Internet Control Message Protocol',
      'Internet Protocol Version 4', 'User Datagram Protocol']);
  check('the quoted addresses are the original datagram\'s',
    allValuesOf(unreachable, 'ip.src'), ['192.0.2.9', '192.0.2.1']);
  check('...and so are the ports', allValuesOf(unreachable, 'udp.srcport'), [51234]);

  // **The columns belong to the router, not to the packet it is describing.**
  // This is the whole difference between quoting and tunnelling: GRE and VXLAN
  // report the inner packet in every column, and an ICMP error must not.
  check('the Source column is the router that complained', unreachable.source, '192.0.2.9');
  check('the Destination column is the host that asked', unreachable.destination, '192.0.2.1');
  check('the Protocol column stays ICMP', unreachable.protocol, 'ICMP');
  check('the Info column is the error', unreachable.info, 'Destination unreachable (Port unreachable)');

  // One key holds one value, so the inner header must not overwrite the outer.
  check('the field bag still answers for the OUTER header',
    fieldValue(unreachable, 'ip.src'), '192.0.2.9');

  check('the unused four bytes are named and shown',
    valueOf(unreachable, 'icmp.unused'), '00:00:00:00');
}

{
  // RFC 792 quotes 64 bits of the original transport header. That is a whole
  // UDP header and it is NOT a whole TCP one - 8 of the 20 bytes - so the
  // quoted IPv4 header dissects and nothing claims to be a TCP segment. The
  // reference draws a truncated TCP subtree here; this build draws none, which
  // is the honest half of the divergence: a 20-byte header read out of 8 bytes
  // would report a window size and an ack number that were never quoted.
  const needed = at('fragmentation needed');
  check('a quote too short for a TCP header grows no TCP layer',
    layerNames(needed),
    ['Frame', 'Ethernet II', 'Internet Protocol Version 4', 'Internet Control Message Protocol',
      'Internet Protocol Version 4']);
  check('the MTU that would have fitted', valueOf(needed, 'icmp.mtu'), 1400);
  check('...and it is filterable', fieldValue(needed, 'icmp.mtu'), 1400);
  check('the quoted header still names the destination that could not be reached',
    allValuesOf(needed, 'ip.dst'), ['192.0.2.1', '198.51.100.1']);
}

{
  const redirect = at('redirect');
  check('the gateway to use instead', valueOf(redirect, 'icmp.redir_gw'), '192.0.2.254');
  check('a redirect quotes the datagram too',
    layerNames(redirect).slice(4), ['Internet Protocol Version 4', 'User Datagram Protocol']);
}

{
  const problem = at('parameter problem');
  check('the offset of the field that was wrong', valueOf(problem, 'icmp.pointer'), 20);
}

{
  const exceeded = at('time exceeded');
  check('time exceeded quotes the datagram', layerNames(exceeded).length, 6);
  check('...and says so in the Info column', exceeded.info,
    'Time-to-live exceeded (Time to live exceeded in transit)');
}

{
  const tooBig = at('packet too big');
  check('an ICMPv6 error quotes an IPv6 datagram',
    layerNames(tooBig),
    ['Frame', 'Ethernet II', 'Internet Protocol Version 6', 'Internet Control Message Protocol v6',
      'Internet Protocol Version 6']);
  check('the MTU the path would accept', valueOf(tooBig, 'icmpv6.mtu'), 1280);
  check('the ICMPv6 checksum covers the pseudo-header',
    valueOf(tooBig, 'icmpv6.checksum.status'), 'Good');
}

// --- no tracker sees a quoted header -----------------------------------------

console.log('\n--- what the quote must not touch ---');
{
  // A quoted TCP header is eight bytes of a segment that was sent once and is
  // being described by somebody else. Handed to `TcpStreamTracker` it would
  // invent a stream, a sequence base and an RTT sample out of a complaint -
  // so the recursion carries no trackers at all, and the observable
  // consequence is that no error frame is on a stream.
  const errors = ['port unreachable', 'fragmentation needed', 'time exceeded', 'redirect'];
  check('no error frame joined a TCP stream',
    errors.map((name) => at(name).streamId), errors.map(() => undefined));
}

// --- the reference agrees ----------------------------------------------------

const TSHARK_CANDIDATES = [
  process.env.TSHARK, 'tshark',
  'C:/Program Files/Wireshark/tshark.exe',
  'C:/Program Files (x86)/Wireshark/tshark.exe',
  '/usr/bin/tshark', '/usr/local/bin/tshark', '/opt/homebrew/bin/tshark',
].filter((p): p is string => typeof p === 'string' && p.length > 0);

function findTshark(): string | null {
  useRepositoryWiresharkProfile();
  for (const candidate of TSHARK_CANDIDATES) {
    if (existsSync(candidate)) return candidate;
    try {
      execFileSync(candidate, ['-v'], { stdio: 'ignore' });
      return candidate;
    } catch { /* not here */ }
  }
  return null;
}

const tshark = findTshark();
if (tshark === null) {
  console.log('\nSKIP  tshark not found - the assertions above ran; the cross-check did not.');
} else {
  console.log(`\n--- the reference agrees (${tshark}) ---`);
  // `-e` repeats a field once per occurrence, comma-separated, which is how
  // the reference expresses what this build expresses as repeated tree rows -
  // and it makes the quoted header's address directly comparable.
  const columns = ['icmp.ident', 'icmp.seq', 'icmp.mtu', 'icmp.pointer', 'icmp.redir_gw',
    'icmpv6.mtu', 'ip.src', 'udp.srcport', 'frame.protocols'];
  const out = execFileSync(tshark, ['-r', capture, '-T', 'fields',
    ...columns.flatMap((c) => ['-e', c]), '-E', 'separator=|'], { encoding: 'utf8' });
  const reference = out.trimEnd().split('\n').map((line) => {
    const cells = line.replace(/\r$/, '').split('|');
    return Object.fromEntries(columns.map((c, i) => [c, cells[i] ?? ''])) as Record<string, string>;
  });

  const row = (name: string) => reference[FRAMES.findIndex((f) => f.name === name)];

  check('the reference reads the same echo identity',
    [row('echo request')['icmp.ident'], row('echo request')['icmp.seq']], ['4660', '7']);
  check('the reference reads the same MTU', row('fragmentation needed')['icmp.mtu'], '1400');
  check('the reference reads the same pointer', row('parameter problem')['icmp.pointer'], '20');
  check('the reference reads the same gateway', row('redirect')['icmp.redir_gw'], '192.0.2.254');
  check('the reference reads the same ICMPv6 MTU', row('packet too big')['icmpv6.mtu'], '1280');
  // The two addresses the reference reports for one frame ARE the outer header
  // and the quoted one, in that order, which is the same pair this build draws
  // as two `ip.src` rows. It is the closest thing to a direct check that the
  // embedded packet is the right packet.
  check('the reference quotes the same two source addresses',
    row('port unreachable')['ip.src'], '192.0.2.9,192.0.2.1');
  check('...and the same quoted port', row('port unreachable')['udp.srcport'], '51234');
  check('the reference nests the quote in its protocol chain',
    row('port unreachable')['frame.protocols'], 'eth:ethertype:ip:icmp:ip:udp');
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All ICMP dissection checks passed.');
process.exit(0);
