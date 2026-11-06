/**
 * Helper, not a test: what `import-worker-equivalence.ts` and its thread entry
 * share - the synthetic inputs, how a row and a store message are reduced to
 * something comparable, and the in-thread end of each route.
 *
 * No exit call here on purpose: `scripts/check.ts` runs a file that has one.
 */
import { createCipheriv, randomBytes } from 'node:crypto';
import type { MessagePort } from 'node:worker_threads';
import { PcapService } from '../../src/services/pcapParser';
import { ImportTail } from '../../src/services/importTail';
import { estimateSummaryBytes } from '../../src/services/bufferBudget';
import { storeMessagesFor } from '../../src/services/capture/storePacket';
import { DerivedStore } from '../../src/services/pipeline/derivedStore';
import { createImportRun } from '../../src/services/pipeline/importRun';
import { SCORING_FRAMES } from '../../src/services/hostIdentity';
import { LIVE_ENV } from '../../src/services/dissect/dissectEnv';
import { fieldEntries } from '../../src/services/dissect/fieldAccess';
import { DSB_SECRETS_TYPE_TLS_KEY_LOG } from '../../src/services/dissect/types';
import { hkdfExpandLabel, SHA256 } from '../../src/services/crypto/hkdf';
import { toHex } from '../../src/services/tls/keyLog';
import { HTTP2_PREFACE } from '../../src/services/dissectors/http2';
import { Bytes, ethernet, internetChecksum, ipv4, pcapOf, tcp, udpFrame } from '../parity/synthetic';
import type { Packet } from '../../src/types/packet';
import type { ImportRunOptions, ToImport } from '../../src/services/pipeline/importProtocol';

// --- how a row and a message are compared -------------------------------------------

/** Not scalars: the field bag and its columns are `fields`, the bytes are `raw`. */
const NOT_SCALAR = new Set(['cols', 'row', 'fields', 'rawBytes', 'layers']);

export interface CanonicalRow {
  scalars: string;
  fields: string;
  raw: string;
}

/** Everything a row says, in an order that does not depend on where a field is kept. */
export function canonicalRow(p: Packet): CanonicalRow {
  const scalars: Record<string, unknown> = {};
  for (const key of Object.keys(p).sort()) {
    if (!NOT_SCALAR.has(key)) scalars[key] = (p as unknown as Record<string, unknown>)[key];
  }
  const fields = fieldEntries(p).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  // Keys sorted at every depth: the codec rebuilds an expert entry's keys in an
  // order of its own, which is not a difference.
  const sorted = (_key: string, value: unknown): unknown =>
    value !== null && typeof value === 'object' && !Array.isArray(value)
      ? Object.fromEntries(Object.entries(value).sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)))
      : value;
  return {
    scalars: JSON.stringify(scalars, sorted),
    fields: JSON.stringify(fields),
    raw: Buffer.from(p.rawBytes.buffer, p.rawBytes.byteOffset, p.rawBytes.byteLength).toString('hex'),
  };
}

/**
 * A value as text, for comparing two of them. Not `v8.serialize`: it writes an
 * integral double as a different tag after one trip through a port than before it,
 * which is not a difference anyone can see. This keeps what matters at a store
 * boundary and nothing else: every key (an absent one and an undefined one differ),
 * each object's prototype by name (a class instance loses it in a clone), and a
 * typed array's type, bytes and the size of the buffer behind it (a clone of a
 * view sends the whole buffer).
 */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return typeof value === 'number' && Object.is(value, -0) ? '-0' : `${typeof value}:${String(value)}`;
  }
  if (ArrayBuffer.isView(value)) {
    const view = value as Uint8Array;
    const bytes = Buffer.from(view.buffer, view.byteOffset, view.byteLength).toString('hex');
    return `${view.constructor.name}[${view.byteLength}/${view.buffer.byteLength}]:${bytes}`;
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const proto = Object.getPrototypeOf(value) as { constructor?: { name?: string } } | null;
  const name = proto === null ? 'null' : proto.constructor?.name ?? '?';
  const keys = Object.keys(value).sort();
  return `${name}{${keys.map((k) => `${k}=${canonical((value as Record<string, unknown>)[k])}`).join(',')}}`;
}

/**
 * A store message minus what is allowed to differ between the routes: the tag, and
 * the credit/barrier slabs, which only the Worker route sends. `null` for a message
 * that is not part of the comparison. The rows are not compared here: the in-process
 * route sends them as `append` and the Worker route as `appendPacked`, so each is
 * decoded to rows (`canonicalRow`) and compared id by id.
 */
export function normalizeStoreMessage(message: unknown): string | null {
  const copy = structuredClone(message) as { type: string; captureId?: string };
  if (copy.type === 'appendBytes' || copy.type === 'append' || copy.type === 'appendPacked') return null;
  delete copy.captureId;
  return canonical(copy);
}

export interface RouteResult {
  /** The store messages that are not rows (the records), normalized, in order. */
  messages: string[];
  /** Every row the store was sent, in order, bytes included. */
  storeRows: CanonicalRow[];
  /** The page's tail at the end. */
  rows: CanonicalRow[];
  estimates: number[];
  totalFrames: number;
  built: number;
  missedPatches: number;
  facts: string;
  derived: [number, string][];
}

export const derivedHex = (entries: [number, Uint8Array][]): [number, string][] =>
  entries.map(([id, bytes]) => [id, Buffer.from(bytes).toString('hex')]);

// --- the in-thread ends of the two routes --------------------------------------------

export type ThreadCommand =
  | { kind: 'inprocess'; blob: Blob; options: ImportRunOptions }
  | { kind: 'msg'; msg: ToImport; port?: MessagePort };

/**
 * The in-process route, as `readStreamedCapture` and App run it: the walk with
 * the default `onSecrets` (this thread's key log), each batch's store messages
 * recorded, the tail kept, the decrypted answers set from the records.
 */
async function inProcess(blob: Blob, options: ImportRunOptions): Promise<RouteResult> {
  const messages: string[] = [];
  const storeRows: CanonicalRow[] = [];
  const tail = new ImportTail({ residentBytes: options.residentBytes, maxFrames: options.maxFrames });
  const derived = new DerivedStore(options.derivedBudget);
  const outcome = await PcapService.streamCaptureFile(blob as File, (batch, records) => {
    for (const message of storeMessagesFor(batch, records)) {
      if (message.type === 'append') for (const row of message.packets) storeRows.push(canonicalRow(row));
      const normal = normalizeStoreMessage(message);
      if (normal !== null) messages.push(normal);
    }
    if (records !== undefined) for (const { id, derived: answers } of records) if (answers) derived.set(id, answers);
    tail.push(batch);
    tail.releaseBytesThrough(batch[batch.length - 1].id);
  }, {
    record: options.record,
    ...(options.patchWindow === undefined ? {} : { patchWindow: options.patchWindow }),
    ...(options.batchFrames === undefined ? {} : { batchFrames: options.batchFrames }),
    ...(options.windowBytes === undefined ? {} : { windowBytes: options.windowBytes }),
  });
  return {
    messages,
    storeRows,
    rows: tail.rows().map(canonicalRow),
    // As `adoptAccounting` takes them: the finished rows' own estimates.
    estimates: tail.rows().map(estimateSummaryBytes),
    totalFrames: outcome.totalFrames,
    built: outcome.built,
    missedPatches: outcome.missedPatches,
    facts: JSON.stringify(outcome.facts),
    derived: derivedHex(derived.entries()),
  };
}

/** The thread's whole behaviour: one route per thread, a fresh isolate and key log each. */
export function threadMain(port: MessagePort): void {
  // A TLS record keeps the wall-clock time its frame was dissected at (the
  // certificate-validity clock, `dissectEnv.now`), so two runs of one route differ
  // by milliseconds in the stored record. Frozen here, in both routes' threads.
  LIVE_ENV.now = () => new Date(1_790_000_000_000);
  let handle: ReturnType<typeof createImportRun> | null = null;
  port.on('message', (command: ThreadCommand) => {
    if (command.kind === 'inprocess') {
      inProcess(command.blob, command.options).then(
        (result) => port.postMessage({ kind: 'result', result }),
        (error: unknown) => port.postMessage({ kind: 'error', message: String(error instanceof Error ? error.stack : error) }),
      );
      return;
    }
    handle ??= createImportRun({
      post: (msg, transfer) => port.postMessage({ kind: 'from', msg }, (transfer ?? []) as ArrayBuffer[]),
    });
    handle(command.msg, command.port === undefined ? [] : [command.port as unknown as globalThis.MessagePort]);
  });
}

// --- synthetic inputs -----------------------------------------------------------------

const u32 = (v: number) => [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
const u16 = (v: number) => [v & 0xff, (v >>> 8) & 0xff];
const pad = (n: number) => new Array((4 - (n % 4)) % 4).fill(0);

function block(type: number, body: number[]): Uint8Array {
  const out = new Uint8Array(12 + body.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, type, true);
  view.setUint32(4, out.length, true);
  out.set(body, 8);
  view.setUint32(out.length - 4, out.length, true);
  return out;
}

const shb = () => block(0x0a0d0d0a, [
  ...u32(0x1a2b3c4d), ...u16(1), ...u16(0), ...u32(0xffffffff), ...u32(0xffffffff),
]);
const idb = () => block(0x00000001, [...u16(1), ...u16(0), ...u32(0)]);
const epb = (data: Uint8Array, index: number) => block(0x00000006, [
  ...u32(0), ...u32(0), ...u32(1_000_000 + index * 1000), ...u32(data.length), ...u32(data.length),
  ...data, ...pad(data.length),
]);
const dsb = (text: string) => {
  const bytes = [...new TextEncoder().encode(text)];
  return block(0x0000000a, [
    ...u32(DSB_SECRETS_TYPE_TLS_KEY_LOG), ...u32(bytes.length), ...bytes, ...pad(bytes.length),
  ]);
};

const concat = (parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
};

// TLS 1.3 over TCP, built byte by byte as `scripts/tls/decrypt.ts` does and sealed
// with Node's own crypto, so nothing here shares an implementation with the
// dissector.

const tlsRecord = (contentType: number, version: number, body: Uint8Array): Uint8Array =>
  concat([Uint8Array.of(contentType, version >> 8, version & 0xff, body.length >> 8, body.length & 0xff), body]);

const handshake = (type: number, body: Uint8Array): Uint8Array =>
  concat([Uint8Array.of(type, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff), body]);

function clientHello(random: Uint8Array): Uint8Array {
  const extensions = Uint8Array.of(
    0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
    0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09, ...Buffer.from('localhost', 'utf8'),
  );
  const body = Uint8Array.of(
    0x03, 0x03, ...random, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00,
    (extensions.length >> 8) & 0xff, extensions.length & 0xff, ...extensions,
  );
  return tlsRecord(22, 0x0301, handshake(1, body));
}

function serverHello(random: Uint8Array): Uint8Array {
  const extensions = Uint8Array.of(0x00, 0x2b, 0x00, 0x02, 0x03, 0x04);
  const body = Uint8Array.of(
    0x03, 0x03, ...random, 0x00, 0x13, 0x01, 0x00,
    (extensions.length >> 8) & 0xff, extensions.length & 0xff, ...extensions,
  );
  return tlsRecord(22, 0x0303, handshake(2, body));
}

/** SETTINGS(empty) and HEADERS(stream 1) with a literal :method/:path, behind the preface. */
function http2Request(): Uint8Array {
  const settings = Uint8Array.of(0, 0, 0, 4, 0, 0, 0, 0, 0);
  const headerBlock = Uint8Array.of(0x82, 0x84, 0x41, 0x09, ...Buffer.from('localhost', 'utf8'));
  const headers = Uint8Array.of(0, 0, headerBlock.length, 1, 0x05, 0, 0, 0, 1, ...headerBlock);
  return concat([HTTP2_PREFACE, settings, headers]);
}

function seal(key: Uint8Array, iv: Uint8Array, sequence: number, inner: Uint8Array): Uint8Array {
  const nonce = Buffer.from(iv);
  for (let i = 0; i < 8; i++) nonce[nonce.length - 1 - i] ^= Math.floor(sequence / 2 ** (8 * i)) & 0xff;
  const plaintext = Buffer.concat([Buffer.from(inner), Buffer.from([23])]);
  const length = plaintext.length + 16;
  const aad = Buffer.from([23, 3, 3, (length >> 8) & 0xff, length & 0xff]);
  const cipher = createCipheriv('aes-128-gcm', Buffer.from(key), nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  return new Uint8Array(Buffer.concat([aad, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]));
}

interface Connection {
  clientPort: number;
  random: Uint8Array;
  clientSecret: Uint8Array;
  serverSecret: Uint8Array;
  clientSeq: number;
  serverSeq: number;
  records: { client: number; server: number };
}

const CLIENT = '192.0.2.10';
const SERVER = '192.0.2.20';

function connection(clientPort: number): Connection {
  return {
    clientPort,
    random: randomBytes(32), clientSecret: randomBytes(32), serverSecret: randomBytes(32),
    clientSeq: 1000, serverSeq: 5000, records: { client: 0, server: 0 },
  };
}

const keyLines = (c: Connection): string =>
  `CLIENT_TRAFFIC_SECRET_0 ${toHex(c.random)} ${toHex(c.clientSecret)}\n`
  + `SERVER_TRAFFIC_SECRET_0 ${toHex(c.random)} ${toHex(c.serverSecret)}\n`;

/** One segment of the connection's TCP stream, `fromClient` choosing the direction. */
function segment(c: Connection, fromClient: boolean, payload: Uint8Array): Uint8Array {
  const [src, dst] = fromClient ? [CLIENT, SERVER] : [SERVER, CLIENT];
  const [sport, dport] = fromClient ? [c.clientPort, 443] : [443, c.clientPort];
  const seq = fromClient ? c.clientSeq : c.serverSeq;
  const ack = fromClient ? c.serverSeq : c.clientSeq;
  if (fromClient) c.clientSeq += payload.length; else c.serverSeq += payload.length;
  return concat([ethernet(0x0800).build(), ipv4(6, tcp(sport, dport, seq, ack, payload), src, dst)]);
}

/** An encrypted record in the connection, at the next sequence number of its direction. */
function appRecord(c: Connection, fromClient: boolean, inner: Uint8Array): Uint8Array {
  const secret = fromClient ? c.clientSecret : c.serverSecret;
  const key = hkdfExpandLabel(secret, 'key', new Uint8Array(0), 16, SHA256);
  const iv = hkdfExpandLabel(secret, 'iv', new Uint8Array(0), 12, SHA256);
  const sequence = fromClient ? c.records.client++ : c.records.server++;
  return segment(c, fromClient, seal(key, iv, sequence, inner));
}

export interface SyntheticInput {
  name: string;
  bytes: Uint8Array;
  /** Rows a tail of this input should be trimmed to, so the trimming is exercised. */
  maxFrames: number;
  /** Frame ids (1-based) of a TLS record before the secrets block, and of one after it. */
  opaqueId?: number;
  decryptedId?: number;
}

/**
 * A pcapng with two TLS 1.3 connections and a Decryption Secrets Block in the
 * middle of the file: connection A's first record comes before it and stays
 * opaque, everything of connection B and A's second record comes after.
 *
 * `fillerFrames` UDP frames come first. Host inference reads the first
 * `SCORING_FRAMES` frames in a pass of its own, which hands over every block it
 * reaches before the main pass dissects anything: with more filler than that, the
 * block is reached by the main pass, in the middle of dissection, as in a big file.
 */
export function tlsWithDsbInput(fillerFrames = 0): SyntheticInput {
  const a = connection(40001);
  const b = connection(40002);
  const hello = (c: Connection) => [
    segment(c, true, clientHello(c.random)),
    segment(c, false, serverHello(randomBytes(32))),
  ];
  const request = http2Request();
  const response = Uint8Array.of(0, 0, 1, 1, 0x04, 0, 0, 0, 1, 0x88);
  const windowUpdate = Uint8Array.of(0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0);
  const frames: Uint8Array[] = [];
  for (let i = 0; i < fillerFrames; i++) frames.push(udpFrame(5000, 9999, Uint8Array.of(i & 0xff)));
  frames.push(...hello(a));
  frames.push(appRecord(a, true, request));
  const before = frames.length;
  // The secrets of both connections, between the frames above and those below.
  const secrets = keyLines(a) + keyLines(b);
  frames.push(...hello(b));
  frames.push(appRecord(b, true, request));
  frames.push(appRecord(b, false, response));
  frames.push(appRecord(b, true, windowUpdate));
  frames.push(appRecord(a, false, response));
  frames.push(appRecord(a, true, windowUpdate));
  const parts: Uint8Array[] = [shb(), idb()];
  frames.forEach((frame, i) => {
    if (i === before) parts.push(dsb(secrets));
    parts.push(epb(frame, i));
  });
  return {
    name: fillerFrames > SCORING_FRAMES
      ? 'a pcapng with TLS 1.3 and a DSB the main pass reaches, past host inference\'s prefix'
      : 'a pcapng with TLS 1.3 and a DSB inside host inference\'s prefix',
    bytes: concat(parts),
    // The tail keeps every TLS frame (twelve rows).
    maxFrames: 12,
    // Only when the main pass reaches the block. Inside the prefix the block is
    // handed over before any frame is dissected (as it is today), so a record
    // "before" it decrypts too, in both routes.
    ...(fillerFrames > SCORING_FRAMES ? { opaqueId: fillerFrames + 3, decryptedId: fillerFrames + 6 } : {}),
  };
}

function dnsPayload(txid: number, response: boolean): Uint8Array {
  const name = [7, ...[...'example'].map((c) => c.charCodeAt(0)), 3, ...[...'com'].map((c) => c.charCodeAt(0)), 0];
  const answer = response
    ? [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]
    : [];
  return Uint8Array.of(
    (txid >> 8) & 0xff, txid & 0xff, response ? 0x81 : 0x01, response ? 0x80 : 0x00,
    0, 1, 0, response ? 1 : 0, 0, 0, 0, 0, ...name, 0, 1, 0, 1, ...answer,
  );
}

function icmpEcho(type: number, id: number, seq: number): Uint8Array {
  const body = new Bytes().u8(type, 0).u16(0, id, seq).build();
  const sum = internetChecksum(body);
  body[2] = (sum >> 8) & 0xff;
  body[3] = sum & 0xff;
  return concat([ethernet(0x0800).build(), ipv4(1, body)]);
}

/**
 * A classic pcap of DNS exchanges, a TCP stream and an ICMP echo whose reply
 * comes further back than the small patch window: `missedPatches` is not zero.
 */
export function dnsTcpInput(): SyntheticInput {
  const frames: Uint8Array[] = [];
  frames.push(icmpEcho(8, 7, 1));
  let seq = 1;
  let ack = 9000;
  for (let i = 0; i < 120; i++) {
    frames.push(udpFrame(0xc000 + i, 53, dnsPayload(i, false)));
    frames.push(udpFrame(53, 0xc000 + i, dnsPayload(i, true)));
    const payload = Uint8Array.from({ length: 30 + (i % 7) }, (_, k) => (i + k) & 0xff);
    frames.push(concat([ethernet(0x0800).build(), ipv4(6, tcp(50000, 80, seq, ack, payload))]));
    seq += payload.length;
    if (i % 25 === 24) ack += 1; // a duplicate and an out-of-step ack for the analysis
  }
  frames.push(icmpEcho(0, 7, 1));
  return { name: 'a classic pcap with DNS, TCP and a late ICMP reply', bytes: pcapOf(frames), maxFrames: 40 };
}
