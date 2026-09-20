/**
 * HTTP/1.1 over TCP, which neither parity fixture contains a single frame of.
 *
 *   npx tsx scripts/http/dissect.ts
 *
 * Both captures were taken on machines whose browsing is entirely HTTPS, so
 * every `http.*` name `tree-coverage.ts` sees in either one comes from SSDP on
 * UDP/1900 - which is HTTP syntax and is checked by the coverage floors, and
 * which exercises none of the things that only happen on a connection: the
 * request/response pairing, `http.time`, a URI with a path and a query, a
 * status line, or a response whose request was never captured.
 *
 * Same move as `scripts/icmp/dissect.ts`, and the same reason: a measurement
 * that cannot see a feature cannot defend it. The frames are built byte by
 * byte, written to a real `.pcap`, dissected by the real parser, and the
 * values are compared against tshark's own answers for the same file.
 */
import { readFileSync, writeFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { Bytes, ethernet, internetChecksum, pcapOf } from '../parity/synthetic';
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

// --- one TCP conversation, built by hand -------------------------------------

const CLIENT = '192.0.2.10';
const SERVER = '198.51.100.20';
const CLIENT_PORT = 51000;

/**
 * An IPv4 header with a correct checksum, between two chosen addresses.
 *
 * `synthetic.ts`'s `ipv4` sends between its documentation pair in one
 * direction only; a conversation needs both, and which side a segment came
 * from is what decides whether it holds a request or a response.
 */
function ip(payload: Uint8Array, src: string, dst: string): Uint8Array {
  const header = new Bytes()
    .u8(0x45, 0x00).u16(20 + payload.length).u16(0x0001).u16(0x4000)
    .u8(64, 6).u16(0).ipv4(src).ipv4(dst).build();
  const sum = internetChecksum(header);
  header[10] = (sum >> 8) & 0xff;
  header[11] = sum & 0xff;
  return Uint8Array.from([...header, ...payload]);
}

/**
 * One TCP segment. The checksum is left zero, which is what a NIC leaves when
 * it will fill it in later and what `checksumVerdict` reads as `Unverified` -
 * so a synthetic segment does not paint itself as damaged.
 */
function segment(fromClient: boolean, seq: number, ack: number, flags: number, body: string): Uint8Array {
  const payload = Uint8Array.from([...body].map((c) => c.charCodeAt(0)));
  const tcp = Uint8Array.from([
    ...new Bytes()
      .u16(fromClient ? CLIENT_PORT : 80, fromClient ? 80 : CLIENT_PORT)
      .u32(seq).u32(ack).u8(0x50, flags).u16(64240, 0, 0).build(),
    ...payload,
  ]);
  return Uint8Array.from([
    ...ethernet(0x0800).build(),
    ...(fromClient ? ip(tcp, CLIENT, SERVER) : ip(tcp, SERVER, CLIENT)),
  ]);
}

const SYN = 0x02, SYN_ACK = 0x12, ACK = 0x10, PSH_ACK = 0x18;

const REQUEST = [
  'GET /search?q=packet+capture&safe=off HTTP/1.1',
  'Host: example.test',
  'User-Agent: inwire-test/1.0',
  'Accept: text/html',
  'Cookie: session=abc123',
  'X-Made-Up: nothing knows this one',
  '', '',
].join('\r\n');

const BODY = '<html>ok</html>';
const RESPONSE = [
  'HTTP/1.1 404 Not Found',
  'Server: inwire-test',
  'Content-Type: text/html; charset=utf-8',
  `Content-Length: ${BODY.length}`,
  'Set-Cookie: session=abc123; Path=/',
  '', '',
].join('\r\n') + BODY;

// A second exchange on the same connection, so the pairing has to be a QUEUE
// rather than "the last request seen": if the two ever crossed, a FIFO is the
// only thing that would notice.
const REQUEST2 = 'HEAD /favicon.ico HTTP/1.1\r\nHost: example.test\r\n\r\n';
const RESPONSE2 = 'HTTP/1.1 200 OK\r\nServer: inwire-test\r\nContent-Length: 0\r\n\r\n';

const FRAMES: { name: string; bytes: Uint8Array }[] = [
  { name: 'syn', bytes: segment(true, 1000, 0, SYN, '') },
  { name: 'syn-ack', bytes: segment(false, 2000, 1001, SYN_ACK, '') },
  { name: 'ack', bytes: segment(true, 1001, 2001, ACK, '') },
  { name: 'request', bytes: segment(true, 1001, 2001, PSH_ACK, REQUEST) },
  { name: 'response', bytes: segment(false, 2001, 1001 + REQUEST.length, PSH_ACK, RESPONSE) },
  { name: 'request2', bytes: segment(true, 1001 + REQUEST.length, 2001 + RESPONSE.length, PSH_ACK, REQUEST2) },
  {
    name: 'response2',
    bytes: segment(false, 2001 + RESPONSE.length, 1001 + REQUEST.length + REQUEST2.length, PSH_ACK, RESPONSE2),
  },
];

// --- dissecting ---------------------------------------------------------------

const directory = mkdtempSync(join(tmpdir(), 'inwire-http-'));
const capture = join(directory, 'http.pcap');
writeFileSync(capture, pcapOf(FRAMES.map((f) => f.bytes)));

const { packets } = await PcapService.parseCaptureFile(
  new File([readFileSync(capture)], 'http.pcap'), Number.POSITIVE_INFINITY, true);

check('every synthetic frame dissected', packets.length, FRAMES.length);

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
const at = (name: string): Packet => packets[FRAMES.findIndex((f) => f.name === name)];

console.log('\n--- the request ---');
{
  const request = at('request');
  check('the Protocol column is HTTP', request.protocolLabel, 'HTTP');
  check('method, target and version', [
    valueOf(request, 'http.request.method'),
    valueOf(request, 'http.request.uri'),
    valueOf(request, 'http.request.version'),
  ], ['GET', '/search?q=packet+capture&safe=off', 'HTTP/1.1']);

  // The decomposition, which is the half of a URI anyone actually filters on.
  check('the path, without the query', valueOf(request, 'http.request.uri.path'), '/search');
  check('one row per path segment', allValuesOf(request, 'http.request.uri.path.segment'), ['search']);
  check('the query, without the mark', valueOf(request, 'http.request.uri.query'),
    'q=packet+capture&safe=off');
  // Three, not two: the reference splits a query on `+` as well as `&` - see
  // `uriRows`, where the reason for following it is written down.
  check('one row per query parameter', allValuesOf(request, 'http.request.uri.query.parameter'),
    ['q=packet', 'capture', 'safe=off']);

  // The authority and the target together, which neither alone carries.
  check('the full request URI', valueOf(request, 'http.request.full_uri'),
    'http://example.test/search?q=packet+capture&safe=off');
  check('presence, for a filter that names no method', valueOf(request, 'http.request'), true);

  check('the named headers', [
    valueOf(request, 'http.host'), valueOf(request, 'http.user_agent'),
    valueOf(request, 'http.accept'), valueOf(request, 'http.cookie'),
  ], ['example.test', 'inwire-test/1.0', 'text/html', 'session=abc123']);
  // A header HTTP has no name for is `http.unknown_header` - which is what
  // makes the field worth having, since it is the only way to ask for one.
  check('a header with no field of its own', allValuesOf(request, 'http.unknown_header'),
    ['nothing knows this one']);
  // Each header's raw line, which the reference emits beside the named field
  // and hides; here it is a child of the row it was parsed from.
  check('every named header keeps its raw line', allValuesOf(request, 'http.request.line'), [
    'Host: example.test',
    'User-Agent: inwire-test/1.0',
    'Accept: text/html',
    'Cookie: session=abc123',
  ]);

  check('the filterable half agrees with the tree',
    [fieldValue(request, 'http.request.method'), fieldValue(request, 'http.host')],
    ['GET', 'example.test']);
}

console.log('\n--- the response, and what it answers ---');
{
  const response = at('response');
  check('status, phrase and version', [
    valueOf(response, 'http.response.code'),
    valueOf(response, 'http.response.phrase'),
    valueOf(response, 'http.response.version'),
  ], [404, 'Not Found', 'HTTP/1.1']);
  check('the status class the reference names', valueOf(response, 'http.response.code.desc'), 'Client Error');
  check('a response is marked as one', valueOf(response, 'http.response'), true);
  check('the response headers', [
    valueOf(response, 'http.server'), valueOf(response, 'http.content_type'),
    valueOf(response, 'http.content_length_header'), valueOf(response, 'http.set_cookie'),
  ], ['inwire-test', 'text/html; charset=utf-8', String(BODY.length), 'session=abc123; Path=/']);

  // **The pairing needed no tracker and no key.** Responses come back in the
  // order the requests went out, which is the only rule RFC 9112 gives, so the
  // queue lives with the connection.
  check('the request this answers', valueOf(response, 'http.request_in'), 4);
  // `pcapOf` stamps consecutive frames one second apart, so the wait is
  // exactly one second and the assertion is exact rather than a tolerance.
  check('...and how long it waited', valueOf(response, 'http.time'), '1.000000000 seconds');
  check('the filter reads seconds, as the reference does',
    fieldValue(response, 'http.time'), 1);

  const second = at('response2');
  check('the second response answers the SECOND request, not the first',
    valueOf(second, 'http.request_in'), 6);
  check('...and waited its own second', valueOf(second, 'http.time'), '1.000000000 seconds');
}

console.log('\n--- what must not happen ---');
{
  // A request has nothing to answer, and a made-up zero would be worse than
  // no row: `http.time == 0` would then match every request in the capture.
  const request = at('request');
  check('a request carries neither pairing row',
    [valueOf(request, 'http.request_in'), valueOf(request, 'http.time')], [undefined, undefined]);
  // The handshake carries no HTTP at all - a dissector that labelled a bare
  // ACK on port 80 as HTTP is where this whole module started.
  // `protocolLabel` is set by whichever subdissector CLAIMS the payload, so a
  // null one is the assertion: nothing claimed these, and the Protocol column
  // falls back to TCP.
  check('the handshake is not HTTP', [
    at('syn').protocolLabel, at('syn-ack').protocolLabel, at('ack').protocolLabel,
  ], [null, null, null]);
}

// --- the reference agrees -----------------------------------------------------

const TSHARK_CANDIDATES = [
  process.env.TSHARK, 'tshark',
  'C:/Program Files/Wireshark/tshark.exe',
  'C:/Program Files (x86)/Wireshark/tshark.exe',
  '/usr/bin/tshark', '/usr/local/bin/tshark', '/opt/homebrew/bin/tshark',
].filter((p): p is string => typeof p === 'string' && p.length > 0);

function findTshark(): string | null {
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
  const columns = [
    'http.request.method', 'http.request.uri', 'http.request.uri.path',
    'http.request.uri.query', 'http.request.uri.query.parameter', 'http.request.full_uri',
    'http.host', 'http.request.line', 'http.response.code', 'http.response.phrase',
    'http.set_cookie', 'http.request_in', 'http.time',
  ];
  const out = execFileSync(tshark, ['-r', capture, '-T', 'fields',
    ...columns.flatMap((c) => ['-e', c]), '-E', 'separator=|'], { encoding: 'utf8' });
  const reference = out.trimEnd().split('\n').map((line) => {
    const cells = line.replace(/\r$/, '').split('|');
    return Object.fromEntries(columns.map((c, i) => [c, cells[i] ?? ''])) as Record<string, string>;
  });
  const row = (name: string) => reference[FRAMES.findIndex((f) => f.name === name)];

  check('the reference reads the same method and target',
    [row('request')['http.request.method'], row('request')['http.request.uri']],
    ['GET', '/search?q=packet+capture&safe=off']);
  check('the reference decomposes the URI the same way',
    [row('request')['http.request.uri.path'], row('request')['http.request.uri.query']],
    ['/search', 'q=packet+capture&safe=off']);
  // `-e` repeats a field once per occurrence, comma separated, which is how
  // the reference expresses what this build draws as repeated rows.
  check('...including the split on `+` this build had to be told about',
    row('request')['http.request.uri.query.parameter'], 'q=packet,capture,safe=off');
  check('the reference builds the same full URI', row('request')['http.request.full_uri'],
    'http://example.test/search?q=packet+capture&safe=off');
  // **The reference files an unknown header two different ways and this is
  // where that shows.** On a TCP connection it is `http.request.line`; in its
  // SSDP dissector's NOTIFY path it is `http.unknown_header` - which is why
  // both names appear in `tree-coverage.ts`'s inwire list, on different
  // frames. This build uses one rule for both, so the line is under
  // `http.unknown_header` here and under `http.request.line` there. Asserted
  // as the divergence it is: the reference HAS the line, and nothing is lost
  // but the choice of which of its two names carries it.
  check('the reference has the same line, under its other name',
    row('request')['http.request.line'].includes('X-Made-Up: nothing knows this one'), true);
  check('the reference reads the same status',
    [row('response')['http.response.code'], row('response')['http.response.phrase']],
    ['404', 'Not Found']);
  check('the reference pairs the response with the same request',
    row('response')['http.request_in'], '4');
  check('...and measures the same wait', row('response')['http.time'], '1.000000000');
  check('the reference pairs the second exchange the same way',
    [row('response2')['http.request_in'], row('response2')['http.time']], ['6', '1.000000000']);
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All HTTP dissection checks passed.');
process.exit(0);
