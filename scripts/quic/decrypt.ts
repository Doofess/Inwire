/**
 * Assertion tests for QUIC packet decryption from a key log, QUIC stream
 * reassembly, and the HTTP/3 that comes out of it.
 *
 *   npx tsx scripts/quic/decrypt.ts
 *
 * A QUIC packet is protected header and all, which is what makes this
 * different from TLS over TCP: there is no visible framing to fall back on, so
 * either the keys are right and the whole packet reads, or nothing does. The
 * packets here are built and protected with Node's crypto - AES-GCM for the
 * payload, AES-ECB for the header mask - so a mistake in our nonce, our AAD,
 * our sample offset or the number of first-byte bits we unmask shows up as a
 * packet that will not open.
 *
 * The stream section matters for a reason peculiar to QUIC: STREAM frames
 * carry explicit offsets and arrive in whatever order the network delivers
 * them, so a fragment ahead of a gap has to be held rather than parsed where
 * it landed. That is checked by delivering one out of order on purpose.
 */
import { createCipheriv } from 'node:crypto';
import { cipherSuiteSpec } from '../../src/services/tls/cipherSuites';
import { deriveTrafficKeys, decryptQuicPacket } from '../../src/services/dissectors/quicCrypto';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { dissectHttp3Stream, freshHttp3Stream, buildHttp3Layer } from '../../src/services/dissectors/http3';
import { qpackDecode, qpackStaticEntry, QPACK_STATIC_ENTRIES } from '../../src/services/dissectors/qpack';

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

const bytes = (...values: number[]) => Uint8Array.from(values);
const utf8 = (text: string) => Array.from(new TextEncoder().encode(text));

// --- QPACK -----------------------------------------------------------------------

console.log('--- QPACK (RFC 9204) ---');
check('the static table has its 99 entries', QPACK_STATIC_ENTRIES, 99);
check('index 17 is :method GET', qpackStaticEntry(17), { name: ':method', value: 'GET' });
check('index 25 is :status 200', qpackStaticEntry(25), { name: ':status', value: '200' });
check('index 98 is the last one', qpackStaticEntry(98), { name: 'x-frame-options', value: 'sameorigin' });
check('index 99 does not exist', qpackStaticEntry(99), null);

/** :method GET, :scheme https, :authority localhost, :path /index.html. */
const FIELD_SECTION = bytes(
  0x00, 0x00,                                  // required insert count 0, delta base 0
  0xd1,                                        // indexed, static 17: :method GET
  0xd7,                                        // indexed, static 23: :scheme https
  0x50, 0x09, ...utf8('localhost'),            // literal with static name 0: :authority
  0x51, 0x0b, ...utf8('/index.html'),          // literal with static name 1: :path
);

{
  const decoded = qpackDecode(FIELD_SECTION);
  check('a static-only field section decodes',
    decoded.headers.map((h) => `${h.name}: ${h.value}`),
    [':method: GET', ':scheme: https', ':authority: localhost', ':path: /index.html']);
  check('...with no error', decoded.error, undefined);
}

{
  // An indexed field line naming the dynamic table cannot be resolved from the
  // field section alone, and must say so rather than name a header it guessed.
  const decoded = qpackDecode(bytes(0x01, 0x00, 0x80));
  check('a dynamic table reference is reported, not invented',
    [decoded.headers.length, decoded.error !== undefined], [0, true]);
}

// --- HTTP/3 framing -----------------------------------------------------------------

console.log('\n--- HTTP/3 framing (RFC 9114) ---');

/** A HEADERS frame wrapping the field section above. */
const HEADERS_FRAME = bytes(0x01, FIELD_SECTION.length, ...FIELD_SECTION);

{
  const stream = freshHttp3Stream(true);
  const result = dissectHttp3Stream(HEADERS_FRAME, stream, true);
  check('a HEADERS frame is read', result.frames.map((f) => f.summary),
    ['HEADERS: GET localhost/index.html']);
}

{
  // A control stream opens with a type varint that is not a frame.
  const stream = freshHttp3Stream(false);
  // Stream type 0x00, then SETTINGS with a five-byte payload: a two-byte
  // varint value for one setting and a one-byte varint for the other.
  const control = bytes(0x00, 0x04, 0x05, 0x01, 0x40, 0x64, 0x07, 0x10);
  const result = dissectHttp3Stream(control, stream, false);
  check('a unidirectional stream declares its type', result.streamTypeName, 'Control Stream');
  check('...and its SETTINGS frame is read', result.frames[0].settings,
    [{ id: 1, name: 'QPACK_MAX_TABLE_CAPACITY', value: 100 }, { id: 7, name: 'QPACK_BLOCKED_STREAMS', value: 16 }]);
}

{
  const stream = freshHttp3Stream(false);
  const result = dissectHttp3Stream(bytes(0x02, 0x3f, 0x00), stream, false);
  check('the QPACK encoder stream is named rather than parsed as frames',
    [result.streamTypeName, result.frames.length], ['QPACK Encoder Stream', 0]);
}

{
  // A frame split across arrivals, which is the ordinary case: a QUIC packet
  // is ~1200 bytes and a header block can be larger.
  const stream = freshHttp3Stream(true);
  const first = dissectHttp3Stream(HEADERS_FRAME.subarray(0, 8), stream, true);
  const second = dissectHttp3Stream(HEADERS_FRAME.subarray(8), stream, true);
  check('a split frame yields nothing on the first half', first.frames.length, 0);
  check('...and the whole frame on the second', second.frames.map((f) => f.summary),
    ['HEADERS: GET localhost/index.html']);
}

// --- stream reassembly, in and out of order ------------------------------------------

console.log('\n--- QUIC stream reassembly ---');
{
  const tracker = new QuicFlowTracker();
  const split = 8;
  // Delivered tail first, which QUIC is free to do and TCP is not.
  const outOfOrder = tracker.readStreams('10.0.0.1', 50000, '10.0.0.2', 443, [
    { streamId: 0, offset: split, data: HEADERS_FRAME.subarray(split), fin: false },
  ]);
  check('a fragment ahead of a gap yields nothing yet', outOfOrder.length, 0);

  const completed = tracker.readStreams('10.0.0.1', 50000, '10.0.0.2', 443, [
    { streamId: 0, offset: 0, data: HEADERS_FRAME.subarray(0, split), fin: false },
  ]);
  check('...and the gap being filled releases both',
    completed.map((s) => s.frames.map((f) => f.summary)), [['HEADERS: GET localhost/index.html']]);

  const layer = buildHttp3Layer(completed);
  check('the layer names the stream and the request',
    layer === null ? null : [layer.layer.name, layer.info.join(', '), layer.fields['http3.headers.path']],
    ['HyperText Transfer Protocol Version 3', 'HEADERS: GET localhost/index.html', '/index.html']);
}

{
  // A retransmitted fragment overlapping what was already read must not be
  // read twice - the frames would be reported a second time.
  const tracker = new QuicFlowTracker();
  tracker.readStreams('10.0.0.1', 50000, '10.0.0.2', 443, [
    { streamId: 0, offset: 0, data: HEADERS_FRAME, fin: false },
  ]);
  const again = tracker.readStreams('10.0.0.1', 50000, '10.0.0.2', 443, [
    { streamId: 0, offset: 0, data: HEADERS_FRAME, fin: false },
  ]);
  check('a retransmitted fragment is not read twice', again.length, 0);
}

// --- packet decryption, with Node building the packet ---------------------------------

console.log('\n--- QUIC packet protection (RFC 9001) ---');

/**
 * Builds a protected short-header packet the way a sender does: encrypt the
 * payload, then mask the first byte and the packet number using a sample taken
 * from the ciphertext that was just produced.
 */
function sealShortHeader(
  keys: { key: Uint8Array; iv: Uint8Array; headerProtection: Uint8Array },
  connectionId: Uint8Array,
  packetNumber: number,
  payload: Uint8Array
): Uint8Array {
  const pnLength = 2;
  const header = Buffer.concat([
    Buffer.from([0x40 | (pnLength - 1)]),
    Buffer.from(connectionId),
    Buffer.from([(packetNumber >> 8) & 0xff, packetNumber & 0xff]),
  ]);

  const nonce = Buffer.from(keys.iv);
  for (let i = 0; i < 8; i++) nonce[nonce.length - 1 - i] ^= Math.floor(packetNumber / 2 ** (8 * i)) & 0xff;

  const cipher = createCipheriv('aes-128-gcm', Buffer.from(keys.key), nonce, { authTagLength: 16 });
  cipher.setAAD(header);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(payload)), cipher.final(), cipher.getAuthTag()]);

  const packet = Buffer.concat([header, ciphertext]);
  // The sample starts four bytes past the packet number field, regardless of
  // how long the packet number actually is - the sender does not know how long
  // the receiver will think it is until it has unmasked the first byte.
  const pnOffset = 1 + connectionId.length;
  const sample = packet.subarray(pnOffset + 4, pnOffset + 20);
  const mask = createCipheriv('aes-128-ecb', Buffer.from(keys.headerProtection), null).update(sample);

  packet[0] ^= mask[0] & 0x1f;
  for (let i = 0; i < pnLength; i++) packet[pnOffset + i] ^= mask[1 + i];
  return new Uint8Array(packet);
}

{
  const suite = cipherSuiteSpec(0x1301)!;
  const secret = new Uint8Array(32).fill(0x5a);
  const keys = deriveTrafficKeys(secret, suite);
  const connectionId = bytes(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88);

  // A STREAM frame on stream 0 carrying the HEADERS frame.
  const streamFrame = bytes(0x0e, 0x00, 0x00, HEADERS_FRAME.length, ...HEADERS_FRAME);
  const packet = sealShortHeader(keys, connectionId, 7, streamFrame);

  const opened = decryptQuicPacket(packet, 0, 1 + connectionId.length, packet.length, keys, -1, false);
  check('a short-header packet opens and its number is recovered', opened?.packetNumber, 7);
  check('...and its payload is the STREAM frame that went in',
    opened === null ? null : Array.from(opened.payload), Array.from(streamFrame));

  // The five-bit first-byte mask is what separates a short header from a long
  // one; unmasking four bits leaves the key phase bit set and the AAD wrong.
  check('unmasking a short header as a long one fails',
    decryptQuicPacket(packet, 0, 1 + connectionId.length, packet.length, keys, -1, true), null);

  // A different connection's keys must not open it.
  const otherKeys = deriveTrafficKeys(new Uint8Array(32).fill(0x5b), suite);
  check('another connection\'s keys do not open it',
    decryptQuicPacket(packet, 0, 1 + connectionId.length, packet.length, otherKeys, -1, false), null);

  // The connection id length is not on the wire; getting it wrong moves the
  // packet number field and the sample, and nothing opens.
  check('the wrong connection id length fails rather than producing noise',
    decryptQuicPacket(packet, 0, 1 + connectionId.length - 1, packet.length, keys, -1, false), null);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All QUIC decryption checks passed.');
process.exit(0);
