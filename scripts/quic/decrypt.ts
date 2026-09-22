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
import { keyLog, toHex } from '../../src/services/tls/keyLog';
import { dissectHttp3Stream, freshHttp3Stream, buildHttp3Layer } from '../../src/services/dissectors/http3';
import {
  qpackDecode, qpackStaticEntry, QPACK_STATIC_ENTRIES, QpackTable, qpackReadEncoderStream,
} from '../../src/services/dissectors/qpack';

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
    ['HEADERS: GET https://localhost/index.html']);
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
    ['HEADERS: GET https://localhost/index.html']);
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
    completed.map((s) => s.frames.map((f) => f.summary)), [['HEADERS: GET https://localhost/index.html']]);

  const layer = buildHttp3Layer(completed);
  check('the layer names the stream and the request',
    layer === null ? null : [layer.layer.name, layer.info.join(', '), layer.fields['http3.headers.path']],
    ['HyperText Transfer Protocol Version 3', 'HEADERS: GET https://localhost/index.html', '/index.html']);
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

// --- QPACK's dynamic table ------------------------------------------------------
//
// Two index spaces meet here and confusing them does not throw: it returns a
// real header with the wrong name, which is the worst outcome a decoder has.
// Entries carry an *absolute* index that never repeats; the wire carries
// indices relative to the encoder's insert count, or to the section's Base -
// and a section may also index *forwards* from its Base, because it is allowed
// to reference entries inserted after it was encoded.
//
// So every case below checks the value that came back, never just that one did.

/** A prefix-coded integer (RFC 7541 section 5.1) with `flags` in the high bits. */
function prefixInt(value: number, prefixBits: number, flags: number): number[] {
  const mask = (1 << prefixBits) - 1;
  if (value < mask) return [flags | value];
  const out = [flags | mask];
  let rest = value - mask;
  while (rest >= 128) { out.push((rest % 128) + 128); rest = Math.floor(rest / 128); }
  out.push(rest);
  return out;
}

/** A literal string with a 7-bit length prefix and no Huffman coding. */
function literalString(text: string): number[] {
  const encoded = Array.from(new TextEncoder().encode(text));
  return [...prefixInt(encoded.length, 7, 0), ...encoded];
}

const insertLiteral = (name: string, value: string): number[] =>
  [...prefixInt(name.length, 5, 0x40), ...Array.from(new TextEncoder().encode(name)), ...literalString(value)];
const insertNamed = (staticIndex: number, value: string): number[] =>
  [...prefixInt(staticIndex, 6, 0xc0), ...literalString(value)];
const setCapacity = (capacity: number): number[] => prefixInt(capacity, 5, 0x20);
const duplicate = (relative: number): number[] => prefixInt(relative, 5, 0x00);

/**
 * A field section prefix. The Required Insert Count is sent modulo a window so
 * it stays small (RFC 9204 section 4.5.1.1), and the Base is sent as a signed
 * delta from it - which is the encoding that makes both directions of relative
 * indexing possible inside one section.
 */
function sectionPrefix(requiredInsertCount: number, base: number, maxEntries: number): number[] {
  const encoded = requiredInsertCount === 0 ? 0 : (requiredInsertCount % (2 * maxEntries)) + 1;
  const out = prefixInt(encoded, 8, 0);
  return base >= requiredInsertCount
    ? [...out, ...prefixInt(base - requiredInsertCount, 7, 0)]
    : [...out, ...prefixInt(requiredInsertCount - base - 1, 7, 0x80)];
}

{
  const table = new QpackTable();
  const stream = bytes(
    ...setCapacity(4096),
    ...insertLiteral('x-first', 'one'),
    ...insertLiteral('x-second', 'two'),
    ...insertNamed(0, 'example.com'),   // static index 0 is :authority
    ...duplicate(2),                    // newest-first: 2 back from insert count 3
  );
  const applied = qpackReadEncoderStream(stream, table);
  check('the encoder stream inserts every entry it carries', applied.inserted.length, 4);
  check('...and consumes all of its bytes', applied.used, stream.length);
  check('...leaving the insert count at the number of insertions', table.insertCount, 4);
  check('a name reference resolves against the static table',
    applied.inserted[2], { name: ':authority', value: 'example.com' });
  check('a duplicate names the entry it copied, not the one beside it',
    applied.inserted[3], { name: 'x-first', value: 'one' });

  const maxEntries = table.maxEntries;
  check('MaxEntries is the capacity over the per-entry overhead', maxEntries, 128);

  // Base == insert count: every reference runs backwards from the newest.
  const backwards = bytes(
    ...sectionPrefix(4, 4, maxEntries),
    0x80 | 0,   // indexed, dynamic, relative 0 -> absolute 3
    0x80 | 3,   // indexed, dynamic, relative 3 -> absolute 0
  );
  check('a section resolves its dynamic references in the right order',
    qpackDecode(backwards, table).headers,
    [{ name: 'x-first', value: 'one' }, { name: 'x-first', value: 'one' }]);

  const mixed = bytes(
    ...sectionPrefix(4, 4, maxEntries),
    0x80 | 2,   // absolute 1
    0x80 | 1,   // absolute 2
  );
  check('...including entries that are not the newest',
    qpackDecode(mixed, table).headers,
    [{ name: 'x-second', value: 'two' }, { name: ':authority', value: 'example.com' }]);

  // Base below the insert count, so the section indexes forwards from it. This
  // is the case a decoder that only ever subtracts gets silently wrong.
  const postBase = bytes(
    ...sectionPrefix(4, 1, maxEntries),
    0x10 | 0,   // post-base 0 -> absolute 1
    0x10 | 2,   // post-base 2 -> absolute 3
  );
  check('a post-base index runs forwards from the Base, not backwards',
    qpackDecode(postBase, table).headers,
    [{ name: 'x-second', value: 'two' }, { name: 'x-first', value: 'one' }]);

  // With no table offered, a dynamic reference is reported rather than named.
  const withoutTable = qpackDecode(backwards);
  check('without the table, a dynamic reference is reported rather than guessed',
    withoutTable.headers.length, 0);
  check('...with a reason', withoutTable.error !== undefined, true);
}

{
  // Eviction, where a wrong answer is most plausible: the entry that held an
  // index is gone, and returning whatever now sits at that position would look
  // entirely reasonable.
  const table = new QpackTable();
  qpackReadEncoderStream(bytes(
    ...setCapacity(80),                  // room for two entries of this size
    ...insertLiteral('aaaa', 'aaaa'),    // absolute 0
    ...insertLiteral('bbbb', 'bbbb'),    // absolute 1
    ...insertLiteral('cccc', 'cccc'),    // absolute 2, evicting absolute 0
  ), table);

  check('the insert count counts evicted entries too', table.insertCount, 3);
  check('an evicted absolute index resolves to nothing', table.absolute(0), null);
  check('...and does not shift the entries that survived',
    table.absolute(2), { name: 'cccc', value: 'cccc' });
}

{
  // An instruction split across two QUIC datagrams. Half of one is not an
  // error; the unconsumed tail is what the caller has to keep.
  const table = new QpackTable();
  qpackReadEncoderStream(bytes(...setCapacity(4096)), table);
  const whole = insertLiteral('x-split', 'value');
  const first = qpackReadEncoderStream(Uint8Array.from(whole.slice(0, 4)), table);
  check('a split instruction inserts nothing yet', first.inserted.length, 0);
  check('...and consumes none of its bytes, so the caller keeps them', first.used, 0);

  const second = qpackReadEncoderStream(Uint8Array.from(whole), table);
  check('...and completes once the rest arrives',
    second.inserted, [{ name: 'x-split', value: 'value' }]);
}


// --- a 0-RTT packet must not poison the connection it arrives on ----------------
//
// The keys for a QUIC connection need two facts from opposite directions: the
// client random from the ClientHello and the cipher suite from the ServerHello.
// Any packet the client sends in between asks for keys that cannot exist yet -
// and the derivation's `null` used to be cached, so the verdict stood for the
// life of the connection.
//
// 0-RTT is precisely the packet that arrives in that window; it is client data
// sent before the handshake completes. One of them was enough to make every
// later 1-RTT packet on the connection unreadable. Measured on a real Chrome
// capture, all three connections carrying a 0-RTT packet read as wholly
// undecryptable while every connection without one decrypted normally.
//
// The check drives the real order: hello, a too-early ask, server hello, then a
// packet that must open.

function hello(kind: 1 | 2, cipher: number): Uint8Array {
  const b: number[] = [];
  const u16 = (v: number) => b.push((v >> 8) & 0xff, v & 0xff);
  b.push(0x03, 0x03);
  for (let i = 0; i < 32; i++) b.push(kind === 1 ? i : 0x80 + i);
  b.push(0);
  if (kind === 1) { u16(2); u16(cipher); b.push(1, 0); } else { u16(cipher); b.push(0); }
  u16(0);
  const body = Uint8Array.from(b);
  const out = new Uint8Array(4 + body.length);
  out[0] = kind;
  out[1] = (body.length >> 16) & 0xff;
  out[2] = (body.length >> 8) & 0xff;
  out[3] = body.length & 0xff;
  out.set(body, 4);
  return out;
}

{
  const suite = cipherSuiteSpec(0x1301)!;
  const CLIENT = { ip: '192.0.2.10', port: 50000 };
  const SERVER = { ip: '198.51.100.5', port: 443 };
  const connectionId = bytes(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02);

  // The client random this synthetic ClientHello carries is 0..31.
  const clientRandom = new Uint8Array(32);
  for (let i = 0; i < 32; i++) clientRandom[i] = i;
  const clientSecret = new Uint8Array(32).fill(0x2a);
  const serverSecret = new Uint8Array(32).fill(0x2b);

  keyLog.clear();
  keyLog.add([
    `CLIENT_TRAFFIC_SECRET_0 ${toHex(clientRandom)} ${toHex(clientSecret)}`,
    `SERVER_TRAFFIC_SECRET_0 ${toHex(clientRandom)} ${toHex(serverSecret)}`,
  ].join('\n'));

  const tracker = new QuicFlowTracker();
  const appKeys = deriveTrafficKeys(clientSecret, suite);
  const streamFrame = bytes(0x0e, 0x00, 0x00, HEADERS_FRAME.length, ...HEADERS_FRAME);
  const packet = sealShortHeader(appKeys, connectionId, 7, streamFrame);
  const pnOffset = 1 + connectionId.length;

  // Registers which endpoint is the client. The Initial itself does not open -
  // these are not its keys - but the registration is what the 1-RTT path reads.
  tracker.createInitialDecryptor(CLIENT.ip, CLIENT.port, SERVER.ip, SERVER.port, packet)(
    0, pnOffset, packet.length, 1, connectionId, 'initial');

  tracker.addCryptoFragments(CLIENT.ip, CLIENT.port, SERVER.ip, SERVER.port,
    [{ offset: 0, data: hello(1, 0x1301) }]);

  // The too-early ask. `handshake` rather than `0rtt` on purpose: 0-RTT is now
  // answered ahead of the derivation entirely, so it can no longer reach the
  // cache - but a server that coalesces its Initial and its Handshake packet
  // into one datagram still asks for handshake keys in the window before its
  // own ServerHello has been reassembled. Asking with `0rtt` here passes
  // whether the cache is guarded or not, which is a test that proves nothing;
  // this was checked by putting the bug back.
  const early = tracker.createInitialDecryptor(CLIENT.ip, CLIENT.port, SERVER.ip, SERVER.port, packet)(
    0, pnOffset, packet.length, 1, connectionId, 'handshake');
  check('a packet sent before the ServerHello does not open', early, null);

  tracker.addCryptoFragments(SERVER.ip, SERVER.port, CLIENT.ip, CLIENT.port,
    [{ offset: 0, data: hello(2, 0x1301) }]);

  const opened = tracker.createInitialDecryptor(CLIENT.ip, CLIENT.port, SERVER.ip, SERVER.port, packet)(
    0, pnOffset, packet.length, 1, connectionId, '1rtt');
  check('...and the ServerHello arriving still opens the next 1-RTT packet', opened?.packetNumber, 7);
  check('...with the payload that went in',
    opened == null ? null : Array.from(opened.payload), Array.from(streamFrame));

  keyLog.clear();
}

// --- an evicted flow lets go of its connection ids ---------------------------
//
// `forgetFlow` deleted `flowConnectionIds` at its first statement and then read
// that same map, two dozen lines later, to decide which entries of
// `connectionNumbers` to drop. It iterated nothing, every time, while its own
// comment said it was clearing the ids - so `connectionNumbers` grew for the
// life of the buffer, bounded only by `reset()`, which fires when the capture
// is gone and never on an eviction. On QUIC-heavy browsing that is the one map
// in this tracker with no working cap.
//
// The observable is `connectionNumberFor`: an id belonging to a flow that has
// been evicted must not still resolve. Put the bug back - read
// `this.flowConnectionIds.get(flowKey)` at the sweep instead of before the
// delete - and the second check here fails, because the stale entry answers.
{
  const tracker = new QuicFlowTracker();
  // MAX_FLOWS is 4096, so 4097 distinct flows evicts the oldest.
  const idOf = (n: number) => n.toString(16).padStart(16, '0');
  const firstId = idOf(0);
  tracker.noteLongHeader('10.0.0.1', 1024, '10.0.0.2', 443, [firstId]);
  check('a fresh connection id resolves to its number',
    tracker.connectionNumberFor(firstId), 0);

  for (let i = 1; i <= 4096; i++) {
    tracker.noteLongHeader('10.0.0.1', 1024 + i, '10.0.0.2', 443, [idOf(i)]);
  }

  check('the evicted flow no longer holds its connection id',
    tracker.connectionNumberFor(firstId), undefined);
  // The flow that pushed it out is still there, so this is an eviction rather
  // than the tracker having simply forgotten everything.
  check('...while the newest flow still does',
    tracker.connectionNumberFor(idOf(4096)), 4096);
  // An index is never handed out twice, evictions included (ADR 0014): a number
  // that came back would point a saved filter at a different conversation.
  tracker.noteLongHeader('10.0.0.1', 9999, '10.0.0.2', 443, [idOf(99999)]);
  check('...and a connection after an eviction still gets an unused number',
    tracker.connectionNumberFor(idOf(99999)), 4097);

  tracker.reset();
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All QUIC decryption checks passed.');
process.exit(0);
