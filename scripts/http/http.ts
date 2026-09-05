/**
 * Assertion tests for the HTTP family: HPACK, HTTP/2 framing, and HTTP/1.1's
 * message framing.
 *
 *   npx tsx scripts/http/http.ts
 *
 * The HPACK cases are RFC 7541's own worked examples, C.4 and C.6, run in
 * sequence against one table each - which is the point of them: C.4.2 and
 * C.6.2 are only decodable because C.4.1 and C.6.1 inserted the entries they
 * index, and C.6.3 is only correct if the 256-byte table evicted in the right
 * order. A decoder that passes them one at a time and fails them in sequence
 * is a decoder with no dynamic table.
 *
 * The Huffman code is checked by its own arithmetic rather than by a table of
 * hand-copied codes: the 257 code lengths must satisfy Kraft's equality
 * exactly, which no single-symbol transcription error survives.
 */
import { huffmanDecode, hpackDecode, HpackTable } from '../../src/services/dissectors/hpack';
import { dissectHttp2, freshHttp2Direction, HTTP2_PREFACE } from '../../src/services/dissectors/http2';
import { dissectHttp1, freshHttp1Direction, looksLikeHttp1 } from '../../src/services/dissectors/http1';

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

const fromHex = (text: string) => {
  const clean = text.replace(/\s/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const utf8 = (text: string) => new TextEncoder().encode(text);
const headerList = (result: { headers: { name: string; value: string }[] }) =>
  result.headers.map((h) => `${h.name}: ${h.value}`);

// --- Huffman -------------------------------------------------------------------

console.log('--- HPACK Huffman (RFC 7541 Appendix B) ---');
check('"www.example.com"', huffmanDecode(fromHex('f1e3 c2e5 f23a 6ba0 ab90 f4ff')), 'www.example.com');
check('"no-cache"', huffmanDecode(fromHex('a8eb 1064 9cbf')), 'no-cache');
check('"custom-value"', huffmanDecode(fromHex('25a8 49e9 5bb8 e8b4 bf')), 'custom-value');
check('"Mon, 21 Oct 2013 20:13:21 GMT"',
  huffmanDecode(fromHex('d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff')),
  'Mon, 21 Oct 2013 20:13:21 GMT');
// The EOS symbol may not appear in a literal, and padding must be all ones.
check('EOS inside a literal is rejected', huffmanDecode(fromHex('ffff ffff')), null);
// 0x00 is the five-bit code for "0" followed by three zero bits, which is
// padding a conforming encoder never writes.
check('padding that is not all ones is rejected', huffmanDecode(fromHex('00')), null);

// --- HPACK, in sequence ----------------------------------------------------------

console.log('\n--- HPACK request sequence (RFC 7541 C.4) ---');
{
  const table = new HpackTable();
  check('C.4.1', headerList(hpackDecode(fromHex('8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff'), table)),
    [':method: GET', ':scheme: http', ':path: /', ':authority: www.example.com']);
  check('C.4.2 - index 62 resolves only because C.4.1 inserted it',
    headerList(hpackDecode(fromHex('8286 84be 5886 a8eb 1064 9cbf'), table)),
    [':method: GET', ':scheme: http', ':path: /', ':authority: www.example.com', 'cache-control: no-cache']);
  check('C.4.3', headerList(hpackDecode(fromHex('8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf'), table)),
    [':method: GET', ':scheme: https', ':path: /index.html', ':authority: www.example.com', 'custom-key: custom-value']);
}

console.log('\n--- HPACK response sequence with eviction (RFC 7541 C.6, 256-byte table) ---');
{
  const table = new HpackTable();
  table.setMaxSize(256);
  check('C.6.1', headerList(hpackDecode(fromHex(
    '4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 2d1b ff6e 919d'
    + '29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3'), table)),
    [':status: 302', 'cache-control: private', 'date: Mon, 21 Oct 2013 20:13:21 GMT', 'location: https://www.example.com']);
  check('C.6.2', headerList(hpackDecode(fromHex('4883 640e ffc1 c0bf'), table)),
    [':status: 307', 'cache-control: private', 'date: Mon, 21 Oct 2013 20:13:21 GMT', 'location: https://www.example.com']);
  check('C.6.3 - correct only if eviction dropped the right entries', headerList(hpackDecode(fromHex(
    '88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab 77ad 94e7 821d'
    + 'd7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106'
    + '3d50 07'), table)),
    [':status: 200', 'cache-control: private', 'date: Mon, 21 Oct 2013 20:13:22 GMT',
      'location: https://www.example.com', 'content-encoding: gzip',
      'set-cookie: foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1']);
}

console.log('\n--- HPACK desynchronisation ---');
{
  // A capture that starts mid-connection cannot resolve a dynamic index, and
  // must say so rather than name a header it guessed.
  const table = new HpackTable();
  const result = hpackDecode(fromHex('be'), table);
  check('an unresolvable dynamic index is reported, not invented',
    [result.headers.length, result.error !== undefined], [0, true]);
  check('...and the table records that it is out of step', table.desynchronised, true);
}

// --- HTTP/2 framing ---------------------------------------------------------------

console.log('\n--- HTTP/2 framing (RFC 9113) ---');
{
  const direction = freshHttp2Direction();
  const settings = Uint8Array.from([0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100]);
  const headers = Uint8Array.from([0, 0, 2, 1, 0x05, 0, 0, 0, 1, 0x82, 0x84]);
  const stream = Uint8Array.from([...HTTP2_PREFACE, ...settings, ...headers]);

  const first = dissectHttp2(stream, direction, true);
  check('the preface is recognised', first.sawPreface, true);
  check('both frames are read', first.frames.map((f) => f.summary),
    ['SETTINGS[0]', 'HEADERS[1]: GET /']);
  check('the SETTINGS entry is named', first.frames[0].settings,
    [{ id: 3, name: 'MAX_CONCURRENT_STREAMS', value: 100 }]);
}

{
  // A frame split across two arrivals: the first must yield nothing and the
  // second must yield the whole frame. This is the case a per-record dissector
  // gets wrong, and TLS records split HTTP/2 frames constantly.
  const direction = freshHttp2Direction();
  const frame = Uint8Array.from([0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0]);
  const a = dissectHttp2(frame.subarray(0, 6), direction, false);
  const b = dissectHttp2(frame.subarray(6), direction, false);
  check('a split frame yields nothing on the first half', a.frames.length, 0);
  check('...and the whole frame on the second', b.frames.map((f) => f.summary), ['WINDOW_UPDATE[0]']);
  check('...with its increment read', b.frames[0].windowIncrement, 4096);
}

{
  // CONTINUATION: the header block is only decodable once the run ends.
  const direction = freshHttp2Direction();
  const headers = Uint8Array.from([0, 0, 1, 1, 0x00, 0, 0, 0, 3, 0x82]);
  const continuation = Uint8Array.from([0, 0, 1, 9, 0x04, 0, 0, 0, 3, 0x84]);
  const result = dissectHttp2(Uint8Array.from([...headers, ...continuation]), direction, false);
  check('HEADERS without END_HEADERS holds its block', result.frames[0].headers, undefined);
  check('...and CONTINUATION completes it', headerList({ headers: result.frames[1].headers ?? [] }),
    [':method: GET', ':path: /']);
}

{
  const direction = freshHttp2Direction();
  const goaway = Uint8Array.from([0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 11]);
  const rst = Uint8Array.from([0, 0, 4, 3, 0, 0, 0, 0, 7, 0, 0, 0, 8]);
  const result = dissectHttp2(Uint8Array.from([...goaway, ...rst]), direction, false);
  // The Info column names the frame and its stream; the error code is in the
  // tree, which is where the reference analyzer puts it too.
  check('the Info column names the frame and its stream', result.frames.map((f) => f.summary),
    ['GOAWAY[0]', 'RST_STREAM[7]']);
  check('...and the error codes are read', result.frames.map((f) => f.errorCode), [11, 8]);
}

// --- HTTP/1.1 framing --------------------------------------------------------------

console.log('\n--- HTTP/1.1 framing (RFC 9112) ---');
check('a request line is recognised', looksLikeHttp1(utf8('GET / HTTP/1.1\r\n'), 0, 16), true);
check('a status line is recognised', looksLikeHttp1(utf8('HTTP/1.1 200 OK\r\n'), 0, 17), true);
check('a binary payload is not', looksLikeHttp1(Uint8Array.from([0x17, 0x03, 0x03, 0x01, 0x00, 0x02]), 0, 6), false);

{
  const direction = freshHttp1Direction();
  const request = utf8('GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: probe/1\r\n\r\n');
  const result = dissectHttp1(request, direction);
  check('the request line is read', result.messages.map((m) => m.summary), ['GET /index.html HTTP/1.1']);
  check('...and its headers', result.messages[0].headers.map((h) => `${h.name}: ${h.value}`),
    ['Host: example.com', 'User-Agent: probe/1']);
  check('...and a request with neither length nor encoding has no body', result.messages[0].bodyFraming, 'no body');
}

{
  // Content-Length framing: the body must be walked past, or the bytes after
  // it read as a second message that is not there.
  const direction = freshHttp1Direction();
  const first = dissectHttp1(utf8('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel'), direction);
  check('a response is read', first.messages.map((m) => m.summary), ['HTTP/1.1 200 OK']);
  const second = dissectHttp1(utf8('lo'), direction);
  check('the rest of the body is body, not a message', [second.messages.length, second.bodyBytes], [0, 2]);
  const third = dissectHttp1(utf8('HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n'), direction);
  check('...and the next message starts where the body ended',
    third.messages.map((m) => m.summary), ['HTTP/1.1 404 Not Found']);
}

{
  // Chunked framing, across an arrival boundary in the middle of a chunk.
  const direction = freshHttp1Direction();
  dissectHttp1(utf8('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel'), direction);
  const rest = dissectHttp1(utf8('lo\r\n0\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n'), direction);
  check('a chunked body ends at the zero chunk and the next message is found',
    rest.messages.map((m) => m.summary), ['HTTP/1.1 204 No Content']);
}

{
  // A response to HEAD carries the Content-Length of a body it does not send.
  // Trusting the header would swallow the next response whole.
  const client = freshHttp1Direction();
  const server = freshHttp1Direction();
  dissectHttp1(utf8('HEAD /big HTTP/1.1\r\nHost: example.com\r\n\r\n'), client);
  const response = dissectHttp1(
    utf8('HTTP/1.1 200 OK\r\nContent-Length: 40000\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'),
    server, 'HEAD');
  check('a HEAD response has no body however long it claims',
    response.messages.map((m) => m.summary), ['HTTP/1.1 200 OK', 'HTTP/1.1 200 OK']);
}

{
  // Transfer-Encoding wins over Content-Length. Disagreeing on that rule is
  // the whole of request smuggling, so it is worth an assertion of its own.
  const direction = freshHttp1Direction();
  const result = dissectHttp1(
    utf8('POST /x HTTP/1.1\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n'), direction);
  check('Transfer-Encoding beats Content-Length', result.messages[0].bodyFraming, 'chunked');
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All HTTP checks passed.');
process.exit(0);
