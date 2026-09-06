/**
 * Assertion tests for TLS decryption from a key log, end to end.
 *
 *   npx tsx scripts/tls/decrypt.ts
 *
 * The oracle is Node's own crypto, deliberately. Records are *encrypted* here
 * with `crypto.createCipheriv` and the app's dissector is asked to read them
 * back, so nothing in this file shares an implementation with the thing it is
 * testing: if our GCM, our ChaCha20-Poly1305, our nonce construction or our
 * AAD layout were wrong, the tag would fail and the record would stay opaque.
 * The key schedule is checked the same way - HKDF-Expand-Label is written out
 * a second time against Node's HMAC and compared, because the label string is
 * the one part of it a reimplementation gets wrong silently.
 *
 * The last section is the whole path: a synthetic TLS 1.3 connection built
 * byte by byte, a key log loaded, and the dissector asked what the frames say.
 * That is the check that fails if the decryption is right but the wiring is
 * not - the epoch tracking, the record sequence numbering, the direction's
 * role, the buffering of application data, the hand-off to HTTP/2.
 */
import { createCipheriv, createHmac, type CipherGCMTypes } from 'node:crypto';
import { hkdfExpandLabel, SHA256, SHA384, tls12Prf } from '../../src/services/crypto/hkdf';
import { cipherSuiteSpec } from '../../src/services/tls/cipherSuites';
import { decryptRecord, deriveFromKeyLog } from '../../src/services/tls/decrypt';
import { keyLog, toHex } from '../../src/services/tls/keyLog';
import { expandKeyCached } from '../../src/services/crypto/aes';
import { dissectTlsSegment } from '../../src/services/dissectors/tls';
import { freshTlsConversation, freshTlsCursor } from '../../src/services/tcpStreamTracker';
import { HTTP2_PREFACE } from '../../src/services/dissectors/http2';

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

const bytes = (...values: number[]) => Uint8Array.from(values);
const filled = (length: number, value: number) => new Uint8Array(length).fill(value);

// --- HKDF-Expand-Label, written a second time against Node's HMAC -------------

function expandLabelIndependently(
  hash: 'sha256' | 'sha384',
  secret: Uint8Array,
  label: string,
  length: number
): Uint8Array {
  const full = Buffer.from(`tls13 ${label}`, 'utf8');
  const info = Buffer.concat([
    Buffer.from([(length >> 8) & 0xff, length & 0xff, full.length]),
    full,
    Buffer.from([0]),
  ]);

  const out = Buffer.alloc(length);
  let previous = Buffer.alloc(0);
  let done = 0;
  for (let counter = 1; done < length; counter++) {
    previous = createHmac(hash, secret)
      .update(Buffer.concat([previous, info, Buffer.from([counter])]))
      .digest();
    const take = Math.min(previous.length, length - done);
    previous.copy(out, done, 0, take);
    done += take;
  }
  return new Uint8Array(out);
}

{
  const secret = filled(32, 0x2b);
  check('HKDF-Expand-Label "key" matches an independent expansion',
    toHex(hkdfExpandLabel(secret, 'key', new Uint8Array(0), 16, SHA256)),
    toHex(expandLabelIndependently('sha256', secret, 'key', 16)));
  check('...and "iv"',
    toHex(hkdfExpandLabel(secret, 'iv', new Uint8Array(0), 12, SHA256)),
    toHex(expandLabelIndependently('sha256', secret, 'iv', 12)));

  const secret384 = filled(48, 0x7c);
  check('...and over SHA-384, where a 48-byte secret and a 32-byte key differ in length',
    toHex(hkdfExpandLabel(secret384, 'key', new Uint8Array(0), 32, SHA384)),
    toHex(expandLabelIndependently('sha384', secret384, 'key', 32)));
}

// --- the TLS 1.2 PRF, likewise -------------------------------------------------

function prfIndependently(
  hash: 'sha256' | 'sha384',
  secret: Uint8Array,
  label: string,
  seed: Uint8Array,
  length: number
): Uint8Array {
  const labelAndSeed = Buffer.concat([Buffer.from(label, 'utf8'), Buffer.from(seed)]);
  const out = Buffer.alloc(length);
  let a = labelAndSeed;
  let done = 0;
  while (done < length) {
    a = createHmac(hash, secret).update(a).digest();
    const block = createHmac(hash, secret).update(Buffer.concat([a, labelAndSeed])).digest();
    const take = Math.min(block.length, length - done);
    block.copy(out, done, 0, take);
    done += take;
  }
  return new Uint8Array(out);
}

{
  const master = filled(48, 0x11);
  const seed = filled(64, 0x22);
  check('the TLS 1.2 PRF matches an independent P_hash',
    toHex(tls12Prf(master, 'key expansion', seed, 72, SHA256)),
    toHex(prfIndependently('sha256', master, 'key expansion', seed, 72)));
}

// --- record decryption, with Node doing the encryption ------------------------

const NODE_CIPHER: Record<string, string> = {
  '0x1301': 'aes-128-gcm',
  '0x1302': 'aes-256-gcm',
  '0x1303': 'chacha20-poly1305',
  '0xc02f': 'aes-128-gcm',
  '0xc030': 'aes-256-gcm',
  '0xcca8': 'chacha20-poly1305',
};

function sealTls13(suite: number, key: Uint8Array, iv: Uint8Array, sequence: number, inner: Uint8Array, innerType: number): Uint8Array {
  const nonce = Buffer.from(iv);
  // Divide rather than shift: JavaScript's `>>` takes its right operand mod 32,
  // so `sequence >> 32` is `sequence` and the top four bytes of the nonce come
  // out wrong for every sequence number above zero. Writing this the obvious
  // way is what the first run of this file did, and the dissector was right.
  for (let i = 0; i < 8; i++) nonce[nonce.length - 1 - i] ^= Math.floor(sequence / 2 ** (8 * i)) & 0xff;

  const plaintext = Buffer.concat([Buffer.from(inner), Buffer.from([innerType])]);
  const length = plaintext.length + 16;
  const aad = Buffer.from([23, 3, 3, (length >> 8) & 0xff, length & 0xff]);

  const cipher = createCipheriv(NODE_CIPHER[`0x${suite.toString(16).padStart(4, '0')}`] as CipherGCMTypes, Buffer.from(key), nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return new Uint8Array(Buffer.concat([aad, body]));
}

for (const suite of [0x1301, 0x1302, 0x1303]) {
  const spec = cipherSuiteSpec(suite)!;
  const name = spec.name;

  keyLog.clear();
  const clientRandom = filled(32, 0x33);
  const serverRandom = filled(32, 0x44);
  const clientApp = filled(spec.hash.digestLength, 0x55);
  const serverApp = filled(spec.hash.digestLength, 0x66);
  keyLog.add([
    `CLIENT_HANDSHAKE_TRAFFIC_SECRET ${toHex(clientRandom)} ${toHex(filled(spec.hash.digestLength, 0x77))}`,
    `SERVER_HANDSHAKE_TRAFFIC_SECRET ${toHex(clientRandom)} ${toHex(filled(spec.hash.digestLength, 0x88))}`,
    `CLIENT_TRAFFIC_SECRET_0 ${toHex(clientRandom)} ${toHex(clientApp)}`,
    `SERVER_TRAFFIC_SECRET_0 ${toHex(clientRandom)} ${toHex(serverApp)}`,
  ].join('\n'));

  const keys = deriveFromKeyLog(spec, clientRandom, serverRandom, keyLog.secretsFor(clientRandom)!)!;
  check(`${name}: two epochs derived for each direction`, [keys.client.length, keys.server.length], [2, 2]);

  const epoch = keys.client[1];
  const message = Buffer.from('GET / HTTP/1.1\r\n\r\n', 'utf8');
  for (const sequence of [0, 1, 7]) {
    const record = sealTls13(suite, epoch.key, epoch.iv, sequence, message, 23);
    const opened = decryptRecord(keys, epoch, sequence, record[0], (record[1] << 8) | record[2], record.subarray(5));
    check(`${name}: record ${sequence} opens, content type recovered`,
      [opened === null ? null : Buffer.from(opened.plaintext).toString('utf8'), opened?.contentType],
      [message.toString('utf8'), 23]);
  }

  // The sequence number is not on the wire, so getting it wrong has to fail
  // rather than produce something.
  const record = sealTls13(suite, epoch.key, epoch.iv, 3, message, 23);
  check(`${name}: the wrong sequence number is rejected, not guessed at`,
    decryptRecord(keys, epoch, 4, record[0], 0x0303, record.subarray(5)), null);
  check(`${name}: the other direction's keys are rejected`,
    decryptRecord(keys, keys.server[1], 3, record[0], 0x0303, record.subarray(5)), null);
}

// --- TLS 1.2, where the key block is cut from one master secret ----------------

for (const suite of [0xc02f, 0xc030, 0xcca8]) {
  const spec = cipherSuiteSpec(suite)!;
  keyLog.clear();
  const clientRandom = filled(32, 0x91);
  const serverRandom = filled(32, 0x92);
  const master = filled(48, 0x93);
  keyLog.add(`CLIENT_RANDOM ${toHex(clientRandom)} ${toHex(master)}`);

  const keys = deriveFromKeyLog(spec, clientRandom, serverRandom, keyLog.secretsFor(clientRandom)!)!;
  const block = prfIndependently(
    spec.hash === SHA384 ? 'sha384' : 'sha256',
    master, 'key expansion',
    new Uint8Array([...serverRandom, ...clientRandom]),
    2 * spec.keyLength + 2 * spec.ivLength,
  );
  check(`${spec.name}: the client write key is the key block's first slice`,
    toHex(keys.client[0].key), toHex(block.subarray(0, spec.keyLength)));
  check(`${spec.name}: the server write key follows it`,
    toHex(keys.server[0].key), toHex(block.subarray(spec.keyLength, 2 * spec.keyLength)));

  // Seal a record the way TLS 1.2 does, and read it back.
  const sequence = 5;
  const plaintext = Buffer.from('hello', 'utf8');
  const explicit = spec.explicitNonceLength > 0 ? Buffer.from([9, 9, 9, 9, 9, 9, 9, 9]) : Buffer.alloc(0);
  const nonce = spec.explicitNonceLength > 0
    ? Buffer.concat([Buffer.from(keys.client[0].iv), explicit])
    : (() => {
      const n = Buffer.from(keys.client[0].iv);
      for (let i = 0; i < 8; i++) n[n.length - 1 - i] ^= Math.floor(sequence / 2 ** (8 * i)) & 0xff;
      return n;
    })();

  const aad = Buffer.alloc(13);
  aad.writeUInt32BE(0, 0);
  aad.writeUInt32BE(sequence, 4);
  aad[8] = 23; aad[9] = 3; aad[10] = 3;
  aad.writeUInt16BE(plaintext.length, 11);

  const cipher = createCipheriv(NODE_CIPHER[`0x${suite.toString(16).padStart(4, '0')}`] as CipherGCMTypes, Buffer.from(keys.client[0].key), nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  const body = Buffer.concat([explicit, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

  const opened = decryptRecord(keys, keys.client[0], sequence, 23, 0x0303, new Uint8Array(body));
  check(`${spec.name}: a record round-trips through Node's encryption`,
    opened === null ? null : Buffer.from(opened.plaintext).toString('utf8'), 'hello');
}

// --- the whole path: a synthetic TLS 1.3 connection ----------------------------

function record(contentType: number, version: number, body: Uint8Array): Uint8Array {
  const out = new Uint8Array(5 + body.length);
  out[0] = contentType;
  out[1] = version >> 8; out[2] = version & 0xff;
  out[3] = body.length >> 8; out[4] = body.length & 0xff;
  out.set(body, 5);
  return out;
}

function handshake(type: number, body: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + body.length);
  out[0] = type;
  out[1] = (body.length >> 16) & 0xff; out[2] = (body.length >> 8) & 0xff; out[3] = body.length & 0xff;
  out.set(body, 4);
  return out;
}

function clientHello(random: Uint8Array): Uint8Array {
  const extensions = bytes(
    0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,       // supported_versions: TLS 1.3
    0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09,
    ...Buffer.from('localhost', 'utf8'),             // server_name
  );
  const body = new Uint8Array([
    0x03, 0x03, ...random, 0x00,
    0x00, 0x02, 0x13, 0x01,
    0x01, 0x00,
    (extensions.length >> 8) & 0xff, extensions.length & 0xff, ...extensions,
  ]);
  return record(22, 0x0301, handshake(1, body));
}

function serverHello(random: Uint8Array): Uint8Array {
  const extensions = bytes(0x00, 0x2b, 0x00, 0x02, 0x03, 0x04);
  const body = new Uint8Array([
    0x03, 0x03, ...random, 0x00,
    0x13, 0x01, 0x00,
    (extensions.length >> 8) & 0xff, extensions.length & 0xff, ...extensions,
  ]);
  return record(22, 0x0303, handshake(2, body));
}

/** SETTINGS(empty), HEADERS(stream 1) with a literal :method/:path. */
function http2ClientFrames(): Uint8Array {
  const settings = bytes(0, 0, 0, 4, 0, 0, 0, 0, 0);
  // Literal header field with incremental indexing, name from the static table.
  const block = bytes(
    0x82,                                             // :method GET
    0x84,                                             // :path /
    0x41, 0x09, ...Buffer.from('localhost', 'utf8'),  // :authority localhost
  );
  const headers = new Uint8Array([
    0, 0, block.length, 1, 0x05, 0, 0, 0, 1, ...block,
  ]);
  return new Uint8Array([...HTTP2_PREFACE, ...settings, ...headers]);
}

{
  keyLog.clear();
  const clientRandom = filled(32, 0xa1);
  const serverRandom = filled(32, 0xa2);
  const clientApp = filled(32, 0xb1);
  const serverApp = filled(32, 0xb2);
  keyLog.add([
    `CLIENT_TRAFFIC_SECRET_0 ${toHex(clientRandom)} ${toHex(clientApp)}`,
    `SERVER_TRAFFIC_SECRET_0 ${toHex(clientRandom)} ${toHex(serverApp)}`,
  ].join('\n'));

  const clientKeys = {
    key: hkdfExpandLabel(clientApp, 'key', new Uint8Array(0), 16, SHA256),
    iv: hkdfExpandLabel(clientApp, 'iv', new Uint8Array(0), 12, SHA256),
  };
  const serverKeys = {
    key: hkdfExpandLabel(serverApp, 'key', new Uint8Array(0), 16, SHA256),
    iv: hkdfExpandLabel(serverApp, 'iv', new Uint8Array(0), 12, SHA256),
  };

  const conversation = freshTlsConversation();
  const clientCursor = freshTlsCursor();
  const serverCursor = freshTlsCursor();
  let frame = 1;
  const feed = (payload: Uint8Array, cursor: typeof clientCursor) => {
    const outcome = dissectTlsSegment(payload, 0, payload.length, {
      frameId: frame++, cursor, conversation, inOrder: true, segmentSeq: 0, gap: false,
    });
    return outcome.kind === 'tls' ? outcome.result : null;
  };

  const hello = feed(clientHello(clientRandom), clientCursor);
  check('the ClientHello is read and its random kept',
    conversation.clientRandom ? toHex(conversation.clientRandom) : null, toHex(clientRandom));
  check('...and the direction is known to be the client', clientCursor.role, 'client');
  check('...and the row is a Client Hello', hello?.info, 'Client Hello (SNI=localhost)');

  feed(serverHello(serverRandom), serverCursor);
  check('the ServerHello settles the suite', conversation.cipherSuite, 0x1301);
  check('...and the key log opens the conversation', conversation.keys !== null && conversation.keys !== undefined, true);
  check('...with one epoch, since the log has no handshake secrets', conversation.keys?.client.length, 1);

  // The client's first application record: the HTTP/2 preface and two frames.
  const first = sealTls13(0x1301, clientKeys.key, clientKeys.iv, 0, http2ClientFrames(), 23);
  const decrypted = feed(first, clientCursor);
  check('the record is decrypted and read as HTTP/2',
    decrypted?.appProtocolLabel, 'HTTP2');
  check('...and the Info column is the frames, not "Application Data"',
    decrypted?.info, 'Magic, SETTINGS[0], HEADERS[1]: GET /');
  check('...and the HPACK-decoded path is published as a field',
    decrypted?.fields['http2.headers.path'], '/');
  check('...and the frame says it was decrypted',
    decrypted?.fields['inwire.tls.decrypted'], 1);
  check('...and the decrypted layer is offered for the tree',
    decrypted?.appLayers?.map((l) => l.name), ['HyperText Transfer Protocol 2']);

  // The server answers on its own keys and its own sequence numbering.
  const responseHeaders = bytes(0, 0, 1, 1, 0x04, 0, 0, 0, 1, 0x88); // :status 200
  const answer = feed(sealTls13(0x1301, serverKeys.key, serverKeys.iv, 0, responseHeaders, 23), serverCursor);
  check('the server direction decrypts on its own sequence numbering',
    answer?.info, 'HEADERS[1]: 200 OK');

  // A second client record must be at sequence 1, which is state nothing on
  // the wire carries.
  const second = feed(sealTls13(0x1301, clientKeys.key, clientKeys.iv, 1, bytes(0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0), 23), clientCursor);
  check('the next record decrypts at the next sequence number',
    second?.info, 'WINDOW_UPDATE[0]');

  // Without the log, the same bytes stay opaque.
  keyLog.clear();
  const cleanConversation = freshTlsConversation();
  const cleanClient = freshTlsCursor();
  const cleanServer = freshTlsCursor();
  let cleanFrame = 1;
  const feedClean = (payload: Uint8Array, cursor: typeof cleanClient) => {
    const outcome = dissectTlsSegment(payload, 0, payload.length, {
      frameId: cleanFrame++, cursor, conversation: cleanConversation, inOrder: true, segmentSeq: 0, gap: false,
    });
    return outcome.kind === 'tls' ? outcome.result : null;
  };
  feedClean(clientHello(clientRandom), cleanClient);
  feedClean(serverHello(serverRandom), cleanServer);
  const opaque = feedClean(first, cleanClient);
  check('with no key log the same record is Application Data', opaque?.info, 'Application Data');
  check('...and no application protocol is claimed', opaque?.appProtocolLabel, undefined);
}

// --- clearing the key log clears the derived keys ------------------------------
//
// `crypto/aes.ts` caches expanded AES schedules in a map keyed by the KEY BYTES
// themselves. Nothing ever flushed it, so Settings -> Decryption said "Cleared."
// while up to 64 keys and their schedules stayed in memory for the life of the
// page - the one place ADR 0008's "key material is transient" was not true.
//
// Asserted through the cache's own documented contract - the returned array is
// shared, so a hit is the SAME object - rather than by exporting a size for the
// test to read.
{
  const key = new Uint8Array(16).fill(0x2b);
  const first = expandKeyCached(key);
  checkTrue('a derived schedule is cached, not rebuilt', expandKeyCached(key) === first);

  keyLog.clear();

  const afterClear = expandKeyCached(key);
  checkTrue('...and clearing the key log drops it', afterClear !== first);
  check('...having derived the same schedule again', [...afterClear], [...first]);
}

keyLog.clear();

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All TLS decryption checks passed.');
process.exit(0);
