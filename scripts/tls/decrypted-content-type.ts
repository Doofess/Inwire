/**
 * A decrypted TLS 1.3 row carries its INNER content type, and the stream
 * digest's TLS phase line reads it (ADR 0055 deferred minor).
 *
 *   npx tsx scripts/tls/decrypted-content-type.ts
 *
 * TLS 1.3 writes `application_data` (23) on the outside of every record after
 * the ServerHello and puts the real type inside the ciphertext. Before this the
 * row's `tls.record.content_type` stayed 23 for a record the key log had
 * opened, so the digest could not tell the server's decrypted handshake
 * (EncryptedExtensions..Finished) from its application data and marked
 * `application data` at the first of them. The reference reports the inner type
 * under `tls.record.content_type` (and the outer under `tls.record.opaque_type`);
 * so does the row now.
 *
 * A synthetic connection is built here with its own AES-GCM (Node's, not the
 * code under test's), dissected frame by frame, folded into a TLS summary, and
 * written as a pcap for tshark when it is installed.
 */
import { createCipheriv } from 'node:crypto';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { useRepositoryWiresharkProfile } from '../wiresharkProfile';
import { ethernet, ipv4, tcp, pcapOf } from '../parity/synthetic';
import { hkdfExpandLabel, SHA256 } from '../../src/services/crypto/hkdf';
import { keyLog, toHex } from '../../src/services/tls/keyLog';
import { dissectTlsSegment } from '../../src/services/dissectors/tls';
import { freshTlsConversation, freshTlsCursor } from '../../src/services/tcpStreamTracker';
import { foldTls, openTls } from '../../src/services/conversation/tlsSummary';
import type { Packet } from '../../src/types/packet';

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

const filled = (n: number, v: number): Uint8Array => new Uint8Array(n).fill(v);
const bytes = (...b: number[]): Uint8Array => Uint8Array.from(b);

function record(contentType: number, version: number, body: Uint8Array): Uint8Array {
  const out = new Uint8Array(5 + body.length);
  out[0] = contentType; out[1] = version >> 8; out[2] = version & 0xff;
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
  const extensions = bytes(0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04);
  const body = new Uint8Array([
    0x03, 0x03, ...random, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00,
    (extensions.length >> 8) & 0xff, extensions.length & 0xff, ...extensions,
  ]);
  return record(22, 0x0301, handshake(1, body));
}

function serverHello(random: Uint8Array): Uint8Array {
  const extensions = bytes(0x00, 0x2b, 0x00, 0x02, 0x03, 0x04);
  const body = new Uint8Array([
    0x03, 0x03, ...random, 0x00, 0x13, 0x01, 0x00,
    (extensions.length >> 8) & 0xff, extensions.length & 0xff, ...extensions,
  ]);
  return record(22, 0x0303, handshake(2, body));
}

/** TLS_AES_128_GCM_SHA256, sealed by Node. */
function seal(secret: Uint8Array, sequence: number, inner: Uint8Array, innerType: number): Uint8Array {
  const key = hkdfExpandLabel(secret, 'key', new Uint8Array(0), 16, SHA256);
  const nonce = Buffer.from(hkdfExpandLabel(secret, 'iv', new Uint8Array(0), 12, SHA256));
  for (let i = 0; i < 8; i++) nonce[nonce.length - 1 - i] ^= Math.floor(sequence / 2 ** (8 * i)) & 0xff;
  const plaintext = Buffer.concat([Buffer.from(inner), Buffer.from([innerType])]);
  const length = plaintext.length + 16;
  const aad = Buffer.from([23, 3, 3, (length >> 8) & 0xff, length & 0xff]);
  const cipher = createCipheriv('aes-128-gcm', Buffer.from(key), nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  return new Uint8Array(Buffer.concat([aad, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]));
}

const clientRandom = filled(32, 0xa1);
const serverRandom = filled(32, 0xa2);
const clientHs = filled(32, 0xc1);
const serverHs = filled(32, 0xc2);
const clientApp = filled(32, 0xb1);
const serverApp = filled(32, 0xb2);
const KEY_LOG = [
  `CLIENT_HANDSHAKE_TRAFFIC_SECRET ${toHex(clientRandom)} ${toHex(clientHs)}`,
  `SERVER_HANDSHAKE_TRAFFIC_SECRET ${toHex(clientRandom)} ${toHex(serverHs)}`,
  `CLIENT_TRAFFIC_SECRET_0 ${toHex(clientRandom)} ${toHex(clientApp)}`,
  `SERVER_TRAFFIC_SECRET_0 ${toHex(clientRandom)} ${toHex(serverApp)}`,
].join('\n');

interface Wire { fromClient: boolean; payload: Uint8Array; label: string; expectedInner: number | null }
const finished = (): Uint8Array => handshake(20, filled(32, 0x5a));
const encryptedExtensions = (): Uint8Array => handshake(8, bytes(0, 0));
const wire: Wire[] = [
  { fromClient: true, payload: clientHello(clientRandom), label: 'ClientHello', expectedInner: 22 },
  { fromClient: false, payload: serverHello(serverRandom), label: 'ServerHello', expectedInner: 22 },
  { fromClient: false, payload: seal(serverHs, 0, encryptedExtensions(), 22), label: 'server EncryptedExtensions', expectedInner: 22 },
  { fromClient: false, payload: seal(serverHs, 1, finished(), 22), label: 'server Finished', expectedInner: 22 },
  { fromClient: true, payload: seal(clientHs, 0, finished(), 22), label: 'client Finished', expectedInner: 22 },
  { fromClient: true, payload: seal(clientApp, 0, Buffer.from('hello'), 23), label: 'client data', expectedInner: 23 },
  { fromClient: false, payload: seal(serverApp, 0, Buffer.from('world'), 23), label: 'server data', expectedInner: 23 },
];

// --- this build -----------------------------------------------------------------

keyLog.clear();
keyLog.add(KEY_LOG);
const conversation = freshTlsConversation();
const cursors = { client: freshTlsCursor(), server: freshTlsCursor() };
const summary = openTls(0);
const seen: { label: string; inner: unknown; decrypted: unknown }[] = [];
const after: string[][] = [];
wire.forEach((w, i) => {
  const outcome = dissectTlsSegment(w.payload, 0, w.payload.length, {
    frameId: i + 1, cursor: w.fromClient ? cursors.client : cursors.server, conversation,
    inOrder: true, segmentSeq: 0, gap: false,
  });
  const fields = outcome.kind === 'tls' ? outcome.result.fields : {};
  seen.push({ label: w.label, inner: fields['tls.record.content_type'], decrypted: fields['inwire.tls.decrypted'] });
  const row = {
    id: i + 1, relativeTime: i, fields, frameProtocols: ['eth', 'ip', 'tcp', 'tls'],
  } as unknown as Packet;
  foldTls(summary, row, w.fromClient ? 'client' : 'server');
  after.push(summary.phases.map((p) => `${p.side}:${p.phase}`));
});

check('every record carries the content type it holds, outer or inner',
  seen.map((s) => [s.label, s.inner]), wire.map((w) => [w.label, w.expectedInner]));
check('...and the sealed ones say they were decrypted',
  seen.map((s) => s.decrypted === 1), wire.map((_, i) => i >= 2));
check('the server\'s decrypted handshake (EncryptedExtensions, Finished) marks no application data',
  after[3], ['client:ClientHello', 'server:ServerHello']);
check('...nor does the client\'s decrypted Finished', after[4], ['client:ClientHello', 'server:ServerHello']);
check('the client\'s first decrypted application record marks it',
  after[5], ['client:ClientHello', 'server:ServerHello', 'client:application data']);
check('...and so does the server\'s, at that record',
  [after[6], summary.phases.find((p) => p.side === 'server' && p.phase === 'application data')?.frameId],
  [['client:ClientHello', 'server:ServerHello', 'client:application data', 'server:application data'], 7]);

// The client's Finished and its first request in one segment, as a client
// usually sends them: the content type is the first record's (22), and the
// frame still carries application data.
{
  const conv = freshTlsConversation();
  const sides = { client: freshTlsCursor(), server: freshTlsCursor() };
  const merged = openTls(0);
  const joined: Wire[] = [
    ...wire.slice(0, 4),
    { fromClient: true, payload: new Uint8Array(Buffer.concat([wire[4].payload, wire[5].payload])), label: 'client Finished + data', expectedInner: 22 },
  ];
  let last: Record<string, unknown> = {};
  joined.forEach((w, i) => {
    const outcome = dissectTlsSegment(w.payload, 0, w.payload.length, {
      frameId: i + 1, cursor: w.fromClient ? sides.client : sides.server, conversation: conv,
      inOrder: true, segmentSeq: 0, gap: false,
    });
    last = outcome.kind === 'tls' ? outcome.result.fields : {};
    foldTls(merged, { id: i + 1, relativeTime: i, fields: last, frameProtocols: ['eth', 'ip', 'tcp', 'tls'] } as unknown as Packet,
      w.fromClient ? 'client' : 'server');
  });
  check('a Finished and a request in one segment: the content type is the first record\'s',
    last['tls.record.content_type'], 22);
  check('...and that frame marks the client\'s application data',
    merged.phases.find((p) => p.side === 'client' && p.phase === 'application data')?.frameId, 5);
}
keyLog.clear();

// --- the reference --------------------------------------------------------------

function findTshark(): string | null {
  useRepositoryWiresharkProfile();
  for (const candidate of [process.env.TSHARK, 'tshark', 'C:/Program Files/Wireshark/tshark.exe', '/usr/bin/tshark', '/usr/local/bin/tshark', '/opt/homebrew/bin/tshark']) {
    if (typeof candidate !== 'string' || candidate.length === 0) continue;
    if (existsSync(candidate)) return candidate;
    try { execFileSync(candidate, ['-v'], { stdio: 'ignore' }); return candidate; } catch { /* not here */ }
  }
  return null;
}

const tshark = findTshark();
if (tshark === null) {
  console.log('\nSKIP  tshark not found - the assertions above ran; the cross-check did not.');
} else {
  console.log(`\n--- the reference reads the same connection (${tshark}) ---`);
  const dir = mkdtempSync(join(tmpdir(), 'inwire-tls-inner-'));
  const capture = join(dir, 'tls13.pcap');
  const keys = join(dir, 'keys.log');
  let clientSeq = 1000, serverSeq = 5000;
  const frames = wire.map((w) => {
    // Addresses swap with the direction, or tshark sees two streams.
    const frame = Uint8Array.from([
      ...ethernet(0x0800).build(),
      ...(w.fromClient
        ? ipv4(6, tcp(50000, 443, clientSeq, serverSeq, w.payload), '192.0.2.1', '192.0.2.2')
        : ipv4(6, tcp(443, 50000, serverSeq, clientSeq, w.payload), '192.0.2.2', '192.0.2.1')),
    ]);
    if (w.fromClient) clientSeq += w.payload.length; else serverSeq += w.payload.length;
    return frame;
  });
  writeFileSync(capture, pcapOf(frames));
  writeFileSync(keys, `${KEY_LOG}\n`);
  const out = execFileSync(tshark, ['-r', capture, '-o', `tls.keylog_file:${keys}`, '-T', 'fields',
    '-e', 'frame.number', '-e', 'tls.record.content_type', '-e', 'tls.record.opaque_type', '-E', 'separator=|'], { encoding: 'utf8' });
  const theirs = out.trimEnd().split('\n').map((l) => l.replace(/\r$/, '').split('|'));
  console.log(`      ${JSON.stringify(theirs)}`);
  // Where tshark opened the record it reports the inner type under content_type
  // and the outer 23 under opaque_type; ours is the same number.
  check('tshark reads the same inner type for each record in the first-record sense',
    theirs.map((c) => Number((c[1] ?? '').split(',')[0])), wire.map((w) => w.expectedInner));
  check('...and the outer 23 of each sealed record as the opaque type',
    theirs.map((c) => (c[2] ?? '').split(',')[0]), wire.map((_, i) => (i >= 2 ? '23' : '')));
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All decrypted-content-type checks passed.');
