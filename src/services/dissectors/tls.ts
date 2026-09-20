/**
 * TLS record-layer dissection with reassembly across TCP segments.
 *
 * What this exists to get right, in order of how much it changes on screen:
 *
 * 1. **Which frame a record belongs to.** A TLS record is up to 16 KB and a
 *    segment is ~1,400 bytes, so most Application Data records span several
 *    segments. Wireshark labels the frame in which a record COMPLETES with
 *    its contents and every earlier segment of it as plain TCP with a
 *    "[TCP PDU reassembled in N]" suffix. Before this file did the same, the
 *    app labelled the segment carrying the record HEADER instead, and on a
 *    download-heavy capture that put 40% of the rows on the wrong protocol.
 *    The per-direction cursor (`TlsRecordCursor`, owned by the TCP tracker)
 *    is what makes this a single pass: how many bytes the record in progress
 *    still owes, and which frames have carried it.
 *
 * 2. **Which version to print.** TLS 1.3 pins the record layer at 0x0303 and
 *    negotiates the real version in ServerHello's supported_versions, so a
 *    conversation is "TLSv1.2" until the server answers and "TLSv1.3" from
 *    then on, in both directions - and a ClientHello is labelled by its own
 *    handshake version, not its record header. Conversation state lives with
 *    the cursor.
 *
 * 3. **What is in the hellos.** SNI, ALPN, offered and selected versions,
 *    groups and key shares (a 1,216-byte share is a post-quantum one), the
 *    ECH extension with the GREASE-vs-real heuristic, and the JA3/JA3S/JA4
 *    fingerprints computed from exactly the fields the specifications name.
 *    Handshake records that span segments are buffered so a hello with a
 *    post-quantum key share (~1.6 KB, larger than one segment) still parses.
 *
 * The record-level work (cursor, labels, info) is the summary pass of
 * docs/decisions/0001; the tree is built by `buildTlsLayer` from the parsed
 * records and can be called later without touching any state.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import type { TlsConversationState, TlsRecordCursor } from '../tcpStreamTracker';
import { applyGapToCursor } from '../tcpStreamTracker';
import { toHex } from '../addressFormat';
import { md5Hex } from '../crypto/md5';
import { sha256 } from '../crypto/sha256';
import { summarizeCertificate, type CertificateSummary } from './x509';
import {
  ALERT_DESCRIPTION_NAMES, ALERT_LEVEL_NAMES, CONTENT_TYPE_NAMES, EC_POINT_FORMAT_NAMES,
  HANDSHAKE_TYPE_NAMES, PSK_KEY_EXCHANGE_MODE_NAMES, TLS_VERSION_NAMES,
  isGrease, nameAlert, nameCipher, nameExtension, nameGroup, nameSignatureAlgorithm, nameVersion,
} from './tlsTables';
import { cipherSuiteSpec, undecryptableReason } from '../tls/cipherSuites';
import { decryptRecord, deriveFromKeyLog } from '../tls/decrypt';
import { keyLog } from '../tls/keyLog';
import { dissectAppStream, freshAppDirection, type AppStreamResult } from './appStream';

/** One encoder, not one per call - see scripts/perf/hot-path-allocations.ts. */
const utf8Encoder = new TextEncoder();

/**
 * One decoder, not one per call - `new TextDecoder()` is not free and a CPU
 * profile put constructing them at 8% of a dissection run. Stateless without
 * `{stream: true}`, which nothing here uses.
 */
const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

const CT_CHANGE_CIPHER_SPEC = 20;
const CT_ALERT = 21;
const CT_HANDSHAKE = 22;
const CT_APPLICATION_DATA = 23;
/**
 * The highest content type that counts as a record header.
 *
 * 24 (Heartbeat) was the ceiling here, which is every type this build decodes -
 * and that is the wrong question. The ceiling decides what may *resynchronise*
 * a stream, not what may be read, and the reference analyzer's
 * `ssl_is_valid_content_type` runs to 26: 25 is `tls12_cid` (RFC 9146) and 26
 * is the DTLS 1.3 ACK. Stopping at 24 meant a record this build cannot decode
 * could not even end the desynchronised region it began, so the stream stayed
 * lost and every following segment came back `Ignored Unknown Record`.
 */
const CT_MAX = 26;

/**
 * The highest content type that puts an element in the **Info column**.
 *
 * Distinct from `CT_MAX`, and the two answer different questions. `CT_MAX`
 * decides what may resynchronise a stream; this decides what the reader is
 * told about. Asked directly, tshark parses a type-25 record - naming it
 * "Connection ID (25)" in the tree, with its version and length - and writes
 * **nothing** to Info for it, so a frame carrying one followed by trailing
 * bytes reads as a bare `Ignored Unknown Record`. Naming it there produced
 * `Unknown (25), Ignored Unknown Record`, and giving it the ignored wording
 * instead would have printed that wording twice.
 */
const INFO_NAMED_CONTENT_TYPE_MAX = 24;

/** A record body larger than this is not buffered for parsing - nothing in a hello needs it. */
const MAX_BUFFERED_RECORD = 65536;

// Well-known ECH public names. Chrome and Firefox add a GREASE ECH extension
// to every ClientHello, so the extension's presence alone means nothing; a
// real ECH ClientHello carries the provider's public name as its outer SNI.
const ECH_PUBLIC_NAMES = new Set(['cloudflare-ech.com']);

/**
 * True for an outer SNI that names an ECH provider rather than the site.
 *
 * Exported for the passive name map: learning `cloudflare-ech.com` as the name
 * of every address behind Cloudflare's ECH would be worse than learning
 * nothing, because it is a name the traffic really carried and so looks
 * trustworthy.
 */
export function isEchPublicName(name: string): boolean {
  return ECH_PUBLIC_NAMES.has(name.toLowerCase());
}

// --- record parsing ----------------------------------------------------------

interface RecordHeader { contentType: number; version: number; length: number }

/**
 * The handshake facts a QUIC CRYPTO stream yields, parsed by the same code
 * that reads a TLS-over-TCP hello. QUIC carries the TLS handshake without the
 * record layer, so this takes the handshake messages directly.
 */
export function parseQuicHandshake(handshake: Uint8Array): { hello?: HelloFacts; serverHello?: ServerHelloFacts } {
  const out: { hello?: HelloFacts; serverHello?: ServerHelloFacts } = {};
  for (let p = 0; p + 4 <= handshake.length;) {
    const type = handshake[p];
    const len = (handshake[p + 1] << 16) | (handshake[p + 2] << 8) | handshake[p + 3];
    if (p + 4 + len > handshake.length) break;
    const msg = handshake.subarray(p, p + 4 + len);
    if (type === 1) out.hello = parseClientHello(msg, 'q') ?? undefined;
    else if (type === 2) out.serverHello = parseServerHello(msg) ?? undefined;
    p += 4 + len;
  }
  return out;
}

/**
 * Reads a record header at `p`.
 *
 * Two standards, deliberately. On a direction that has not yet shown a
 * record (`strict`), the version and length are checked too: random
 * ciphertext occasionally looks like a content type, but almost never
 * alongside a real version and a length inside TLS's 2^14 + overhead ceiling,
 * and claiming a non-TLS stream for TLS is the worse mistake. On a direction
 * already known to be TLS, Wireshark checks only the content-type byte -
 * a header with version 0x697a and length 39,909 is accepted and reassembled
 * as declared. That is how it resynchronises after a loss ate a real header,
 * and matching it byte for byte is what makes the two views agree on which
 * frame ends a record.
 */
function readRecordHeader(b: Uint8Array, p: number, strict: boolean): RecordHeader | null {
  const contentType = b[p];
  const version = (b[p + 1] << 8) | b[p + 2];
  const length = (b[p + 3] << 8) | b[p + 4];
  if (contentType < CT_CHANGE_CIPHER_SPEC || contentType > CT_MAX) return null;
  if (strict && (TLS_VERSION_NAMES[version] === undefined || length === 0 || length > 0x4800)) return null;
  return { contentType, version, length };
}

/** Whether a plausible record header starts at `p` - the cheap test that decides if a stream gets cursor state. */
export function looksLikeTlsRecord(b: Uint8Array, p: number, end: number): boolean {
  return end - p >= 5 && readRecordHeader(b, p, true) !== null;
}

function headerFromPartial(partial: number[]): RecordHeader | null {
  return readRecordHeader(Uint8Array.from(partial), 0, false);
}

/** One record as seen from the frame that completed it. */
export interface TlsRecord {
  contentType: number;
  version: number;
  length: number;
  /** The body, when it is in this frame or was buffered; null for an unbuffered spanning record. */
  body: Uint8Array | null;
  /** Byte range within this frame for an inline record; absent when it spanned frames. */
  range?: [number, number];
  /** Frames before this one that carried part of the record. */
  reassembledFrom: number[];
  /** Per-frame byte counts for the reassembly note, including this frame. */
  contributions: { frame: number; bytes: number }[];
  /** Filled in by describeRecord. */
  description: string;
  /** Bytes after the last record that do not start another - Wireshark's "Ignored Unknown Record". */
  ignored?: boolean;
  hello?: HelloFacts;
  serverHello?: ServerHelloFacts;
  certificates?: CertificateSummary[];
  alert?: { level: number; description: number };
  handshakeTypes?: number[];
  /** Present when a key log secret opened this record. */
  decrypted?: DecryptedRecordView;
}

/** What came out of a record a key log opened. */
export interface DecryptedRecordView {
  /** The real content type - in TLS 1.3 the header always claims application data. */
  contentType: number;
  plaintextLength: number;
  /** "handshake" or "application": which epoch's keys opened it. */
  epoch: string;
  /** Set when the plaintext was an application protocol this build reads. */
  app?: AppStreamResult;
  /** Set when the plaintext was handshake messages. */
  handshake?: string;
  certificates?: CertificateSummary[];
  alert?: { level: number; description: number };
}

// --- hello parsing -----------------------------------------------------------

export interface Extension { type: number; body: Uint8Array }

export interface HelloFacts {
  version: number;
  random: Uint8Array;
  sessionId: Uint8Array;
  ciphers: number[];
  compression: number[];
  extensions: Extension[];
  sni: string | null;
  alpn: string[];
  supportedVersions: number[];
  groups: number[];
  ecPointFormats: number[];
  signatureAlgorithms: number[];
  keyShares: { group: number; length: number }[];
  pskModes: number[];
  hasPreSharedKey: boolean;
  echPresent: boolean;
  /** Real ECH by the heuristic above, as opposed to GREASE. */
  echReal: boolean;
  ja3: string;
  ja3Full: string;
  ja4: string;
  ja4Raw: string;
}

export interface ServerHelloFacts {
  version: number;
  random: Uint8Array;
  sessionId: Uint8Array;
  cipher: number;
  compression: number;
  extensions: Extension[];
  /** From supported_versions when present - the version actually negotiated. */
  selectedVersion: number | null;
  keyShareGroup: number | null;
  alpn: string | null;
  ja3s: string;
  ja3sFull: string;
}

function u16(b: Uint8Array, p: number): number { return (b[p] << 8) | b[p + 1]; }

function parseExtensions(b: Uint8Array, p: number, end: number): Extension[] {
  const out: Extension[] = [];
  if (p + 2 > end) return out;
  const total = u16(b, p);
  p += 2;
  const stop = Math.min(end, p + total);
  while (p + 4 <= stop) {
    const type = u16(b, p);
    const len = u16(b, p + 2);
    const bodyStart = p + 4;
    if (bodyStart + len > stop) break;
    out.push({ type, body: b.subarray(bodyStart, bodyStart + len) });
    p = bodyStart + len;
  }
  return out;
}

function u16List(body: Uint8Array, lengthBytes: 1 | 2): number[] {
  const out: number[] = [];
  if (body.length < lengthBytes) return out;
  const len = lengthBytes === 2 ? u16(body, 0) : body[0];
  for (let p = lengthBytes; p + 2 <= Math.min(body.length, lengthBytes + len); p += 2) out.push(u16(body, p));
  return out;
}

function parseAlpn(body: Uint8Array): string[] {
  const out: string[] = [];
  if (body.length < 2) return out;
  const len = u16(body, 0);
  const dec = utf8Decoder;
  for (let p = 2; p < Math.min(body.length, 2 + len);) {
    const n = body[p];
    if (p + 1 + n > body.length) break;
    out.push(dec.decode(body.subarray(p + 1, p + 1 + n)));
    p += 1 + n;
  }
  return out;
}

function parseSni(body: Uint8Array): string | null {
  // server_name: list length(2), then entries of type(1) length(2) name.
  if (body.length < 5) return null;
  const listLen = u16(body, 0);
  for (let p = 2; p + 3 <= Math.min(body.length, 2 + listLen);) {
    const type = body[p];
    const n = u16(body, p + 1);
    if (p + 3 + n > body.length) break;
    if (type === 0) return utf8Decoder.decode(body.subarray(p + 3, p + 3 + n));
    p += 3 + n;
  }
  return null;
}

const hex4 = (n: number) => n.toString(16).padStart(4, '0');
const sha256Prefix12 = (s: string) => toHex(sha256(utf8Encoder.encode(s))).slice(0, 12);

function ja4Version(v: number): string {
  switch (v) {
    case 0x0304: return '13';
    case 0x0303: return '12';
    case 0x0302: return '11';
    case 0x0301: return '10';
    case 0x0300: return 's3';
    default: return '00';
  }
}

function ja4Alpn(alpn: string[]): string {
  if (alpn.length === 0) return '00';
  const first = alpn[0];
  if (first.length === 0) return '00';
  const isAlnum = (c: string) => /^[0-9A-Za-z]$/.test(c);
  const a = first[0];
  const z = first[first.length - 1];
  if (isAlnum(a) && isAlnum(z)) return `${a}${z}`;
  const bytes = utf8Encoder.encode(first);
  const h = toHex(bytes);
  return `${h[0]}${h[h.length - 1]}`;
}

export function parseClientHello(body: Uint8Array, transport: 't' | 'q' = 't'): HelloFacts | null {
  // Handshake header: type(1) length(3), then ClientHello.
  if (body.length < 4 + 2 + 32 + 1) return null;
  let p = 4;
  const version = u16(body, p); p += 2;
  const random = body.subarray(p, p + 32); p += 32;
  const sidLen = body[p]; p += 1;
  const sessionId = body.subarray(p, p + sidLen); p += sidLen;
  if (p + 2 > body.length) return null;
  const csLen = u16(body, p); p += 2;
  const ciphers: number[] = [];
  for (let q = p; q + 2 <= Math.min(body.length, p + csLen); q += 2) ciphers.push(u16(body, q));
  p += csLen;
  if (p >= body.length) return null;
  const compLen = body[p]; p += 1;
  const compression = Array.from(body.subarray(p, p + compLen)); p += compLen;
  const extensions = parseExtensions(body, p, body.length);

  const facts: HelloFacts = {
    version, random, sessionId, ciphers, compression, extensions,
    sni: null, alpn: [], supportedVersions: [], groups: [], ecPointFormats: [], signatureAlgorithms: [],
    keyShares: [], pskModes: [], hasPreSharedKey: false, echPresent: false, echReal: false,
    ja3: '', ja3Full: '', ja4: '', ja4Raw: '',
  };
  for (const ext of extensions) {
    switch (ext.type) {
      case 0: facts.sni = parseSni(ext.body); break;
      case 16: facts.alpn = parseAlpn(ext.body); break;
      case 43: facts.supportedVersions = u16List(ext.body, 1); break;
      case 10: facts.groups = u16List(ext.body, 2); break;
      case 11: facts.ecPointFormats = ext.body.length >= 1 ? Array.from(ext.body.subarray(1, 1 + ext.body[0])) : []; break;
      case 13: facts.signatureAlgorithms = u16List(ext.body, 2); break;
      case 45: facts.pskModes = ext.body.length >= 1 ? Array.from(ext.body.subarray(1, 1 + ext.body[0])) : []; break;
      case 41: facts.hasPreSharedKey = true; break;
      case 0xfe0d: facts.echPresent = true; break;
      case 51: {
        if (ext.body.length < 2) break;
        const total = u16(ext.body, 0);
        for (let q = 2; q + 4 <= Math.min(ext.body.length, 2 + total);) {
          const group = u16(ext.body, q);
          const len = u16(ext.body, q + 2);
          facts.keyShares.push({ group, length: len });
          q += 4 + len;
        }
        break;
      }
    }
  }
  facts.echReal = facts.echPresent && facts.sni !== null && ECH_PUBLIC_NAMES.has(facts.sni);

  // JA3: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats - decimal, GREASE removed.
  const noGrease = (xs: number[]) => xs.filter((x) => !isGrease(x));
  facts.ja3Full = [
    String(version),
    noGrease(ciphers).join('-'),
    noGrease(extensions.map((e) => e.type)).join('-'),
    noGrease(facts.groups).join('-'),
    facts.ecPointFormats.join('-'),
  ].join(',');
  facts.ja3 = md5Hex(facts.ja3Full);

  // JA4 (FoxIO, BSD-3 core): t + version + sni + counts + alpn, then two hashes.
  const supported = noGrease(facts.supportedVersions);
  const ja4Ver = ja4Version(supported.length > 0 ? Math.max(...supported) : version);
  const cipherList = noGrease(ciphers).map(hex4);
  const extList = noGrease(extensions.map((e) => e.type));
  const pad2 = (n: number) => String(Math.min(n, 99)).padStart(2, '0');
  const head = `${transport}${ja4Ver}${facts.sni !== null ? 'd' : 'i'}${pad2(cipherList.length)}${pad2(extList.length)}${ja4Alpn(facts.alpn)}`;
  const sortedCiphers = [...cipherList].sort().join(',');
  const sortedExts = extList.filter((t) => t !== 0 && t !== 16).map(hex4).sort().join(',');
  const sigAlgs = facts.signatureAlgorithms.map(hex4).join(',');
  const extString = sigAlgs ? `${sortedExts}_${sigAlgs}` : sortedExts;
  facts.ja4 = `${head}_${sortedCiphers ? sha256Prefix12(sortedCiphers) : '000000000000'}_${sortedExts ? sha256Prefix12(extString) : '000000000000'}`;
  facts.ja4Raw = `${head}_${sortedCiphers}_${extString}`;
  return facts;
}

export function parseServerHello(body: Uint8Array): ServerHelloFacts | null {
  if (body.length < 4 + 2 + 32 + 1) return null;
  let p = 4;
  const version = u16(body, p); p += 2;
  const random = body.subarray(p, p + 32); p += 32;
  const sidLen = body[p]; p += 1;
  const sessionId = body.subarray(p, p + sidLen); p += sidLen;
  if (p + 3 > body.length) return null;
  const cipher = u16(body, p); p += 2;
  const compression = body[p]; p += 1;
  const extensions = parseExtensions(body, p, body.length);
  const facts: ServerHelloFacts = {
    version, random, sessionId, cipher, compression, extensions,
    selectedVersion: null, keyShareGroup: null, alpn: null, ja3s: '', ja3sFull: '',
  };
  for (const ext of extensions) {
    if (ext.type === 43 && ext.body.length >= 2) facts.selectedVersion = u16(ext.body, 0);
    if (ext.type === 51 && ext.body.length >= 2) facts.keyShareGroup = u16(ext.body, 0);
    if (ext.type === 16) facts.alpn = parseAlpn(ext.body)[0] ?? null;
  }
  facts.ja3sFull = [String(version), String(cipher), extensions.map((e) => e.type).join('-')].join(',');
  facts.ja3s = md5Hex(facts.ja3sFull);
  return facts;
}

function parseCertificates(body: Uint8Array): CertificateSummary[] {
  // Certificate: handshake header(4), certificates_length(3), then each len(3) + DER.
  // TLS 1.3 would add a request-context byte first, but 1.3 certificates are encrypted.
  const out: CertificateSummary[] = [];
  if (body.length < 7) return out;
  const total = (body[4] << 16) | (body[5] << 8) | body[6];
  for (let p = 7; p + 3 <= Math.min(body.length, 7 + total);) {
    const len = (body[p] << 16) | (body[p + 1] << 8) | body[p + 2];
    if (p + 3 + len > body.length) break;
    const summary = summarizeCertificate(body.subarray(p + 3, p + 3 + len));
    if (summary) out.push(summary);
    p += 3 + len;
  }
  return out;
}

/**
 * TLS 1.3's Certificate message, which is not the 1.2 one with a byte in front:
 * it opens with a request context and each entry carries its own extensions.
 * Reading it with the 1.2 parser yields a certificate that starts a few bytes
 * late and parses as garbage, which is a more confusing answer than none.
 */
function parseCertificates13(body: Uint8Array): CertificateSummary[] {
  const out: CertificateSummary[] = [];
  if (body.length < 5) return out;
  const contextLength = body[4];
  let p = 5 + contextLength;
  if (p + 3 > body.length) return out;
  const total = (body[p] << 16) | (body[p + 1] << 8) | body[p + 2];
  p += 3;
  const stop = Math.min(body.length, p + total);
  while (p + 3 <= stop) {
    const length = (body[p] << 16) | (body[p + 1] << 8) | body[p + 2];
    if (p + 3 + length > stop) break;
    const summary = summarizeCertificate(body.subarray(p + 3, p + 3 + length));
    if (summary) out.push(summary);
    p += 3 + length;
    if (p + 2 > stop) break;
    p += 2 + ((body[p] << 8) | body[p + 1]);
  }
  return out;
}

// --- decryption ----------------------------------------------------------------

/**
 * Works out whether this conversation can be decrypted, once both hellos have
 * been seen. Runs at most once per key log version: a verdict of "no secret
 * for this connection" is only as good as the log it was reached against, and
 * the user may load one at any moment.
 */
function deriveConversationKeys(conv: TlsConversationState): void {
  if (conv.keys !== undefined && conv.keyGeneration === keyLog.generation) return;
  conv.keyGeneration = keyLog.generation;

  if (conv.clientRandom === undefined || conv.serverRandom === undefined || conv.cipherSuite === undefined) {
    conv.keys = undefined;
    return;
  }

  const spec = cipherSuiteSpec(conv.cipherSuite);
  if (spec === null) {
    conv.keys = null;
    conv.keyNote = undecryptableReason(conv.cipherSuite, nameCipher(conv.cipherSuite)) ?? undefined;
    return;
  }

  const secrets = keyLog.secretsFor(conv.clientRandom);
  if (secrets === undefined) {
    conv.keys = null;
    // Silence when there is no key log at all: an unopened TLS conversation is
    // the normal state of the world, not a finding.
    conv.keyNote = keyLog.isEmpty ? undefined : 'no key log entry for this connection';
    return;
  }

  const keys = deriveFromKeyLog(spec, conv.clientRandom, conv.serverRandom, secrets);
  conv.keys = keys;
  conv.keyNote = keys === null ? 'the key log covers this connection but has no usable secret for it' : undefined;
}

/** True for a record whose body is ciphertext under the conversation's keys. */
function isEncryptedRecord(record: TlsRecord, conv: TlsConversationState, cursor: TlsRecordCursor): boolean {
  if (record.contentType === CT_CHANGE_CIPHER_SPEC) return false;
  // TLS 1.3 hides everything after the ServerHello behind an application-data
  // content type, including the rest of the handshake.
  if ((conv.negotiatedVersion ?? 0) >= 0x0304) return record.contentType === CT_APPLICATION_DATA;
  return cursor.encrypted || record.contentType === CT_APPLICATION_DATA;
}

/**
 * Tries this direction's current epoch, then any later one from sequence zero.
 *
 * There is no signal on the wire that says which epoch a record belongs to -
 * the transition happens when the sender's Finished goes out, which is itself
 * encrypted - so the AEAD tag is the oracle. That is sound precisely because a
 * wrong key fails the tag: a guess cannot succeed by accident.
 */
function decryptIfPossible(
  record: TlsRecord, conv: TlsConversationState, cursor: TlsRecordCursor,
  appFrame?: { id: number; tsUs: number },
): void {
  const keys = conv.keys;
  if (!keys || record.body === null || cursor.role === 'unknown' || cursor.readOnly) return;
  if (!isEncryptedRecord(record, conv, cursor)) return;

  const epochs = cursor.role === 'server' ? keys.server : keys.client;
  for (let index = Math.max(0, cursor.epoch); index < epochs.length; index++) {
    const sequence = index === cursor.epoch ? cursor.recordSeq : 0;
    const opened = decryptRecord(keys, epochs[index], sequence, record.contentType, record.version, record.body);
    if (opened === null) continue;

    cursor.epoch = index;
    cursor.recordSeq = sequence + 1;
    record.decrypted = {
      contentType: opened.contentType,
      plaintextLength: opened.plaintext.length,
      epoch: epochs[index].name,
    };
    readPlaintext(record.decrypted, opened.plaintext, opened.contentType, conv, cursor, appFrame);
    return;
  }
}

function readPlaintext(
  view: DecryptedRecordView,
  plaintext: Uint8Array,
  contentType: number,
  conv: TlsConversationState,
  cursor: TlsRecordCursor,
  /** Which frame the record arrived in, for `http.request_in` / `http.time`. */
  appFrame?: { id: number; tsUs: number },
): void {
  if (contentType === CT_ALERT) {
    if (plaintext.length >= 2) view.alert = { level: plaintext[0], description: plaintext[1] };
    return;
  }

  if (contentType === CT_HANDSHAKE) {
    const parts: string[] = [];
    for (let p = 0; p + 4 <= plaintext.length;) {
      const type = plaintext[p];
      const length = (plaintext[p + 1] << 16) | (plaintext[p + 2] << 8) | plaintext[p + 3];
      if (p + 4 + length > plaintext.length) break;
      const message = plaintext.subarray(p, p + 4 + length);
      if (type === 11) {
        const certificates = parseCertificates13(message);
        if (certificates.length > 0) view.certificates = [...(view.certificates ?? []), ...certificates];
      }
      parts.push(HANDSHAKE_TYPE_NAMES[type] ?? `Handshake (${type})`);
      p += 4 + length;
    }
    view.handshake = parts.join(', ');
    return;
  }

  if (contentType !== CT_APPLICATION_DATA) return;

  const isClient = cursor.role === 'client';
  if (isClient) conv.appClient ??= freshAppDirection();
  else conv.appServer ??= freshAppDirection();
  const own = (isClient ? conv.appClient : conv.appServer)!;
  const peer = isClient ? conv.appServer : conv.appClient;

  const app = dissectAppStream(plaintext, own, isClient, conv.alpn, peer, appFrame);
  if (app.protocolLabel !== null) view.app = app;
}

// --- describing records --------------------------------------------------------

function describeRecord(
  record: TlsRecord, conv: TlsConversationState, cursor: TlsRecordCursor,
  appFrame?: { id: number; tsUs: number },
): void {
  if (record.ignored) return;
  if (TLS_VERSION_NAMES[record.version] !== undefined) conv.lastRecordVersion = record.version;
  const body = record.body;
  switch (record.contentType) {
    case CT_APPLICATION_DATA:
      record.description = 'Application Data';
      decryptIfPossible(record, conv, cursor, appFrame);
      if (record.decrypted) record.description = describeDecrypted(record.decrypted);
      return;
    case CT_CHANGE_CIPHER_SPEC:
      record.description = 'Change Cipher Spec';
      // In TLS 1.2 everything after this in the same direction is encrypted.
      if ((conv.negotiatedVersion ?? 0) < 0x0304) cursor.encrypted = true;
      return;
    case CT_ALERT:
      if (body && body.length === 2 && (body[0] === 1 || body[0] === 2) && ALERT_DESCRIPTION_NAMES[body[1]] !== undefined) {
        record.alert = { level: body[0], description: body[1] };
        record.description = `Alert (${nameAlert(body[0], body[1])})`;
        return;
      }
      decryptIfPossible(record, conv, cursor, appFrame);
      if (record.decrypted?.alert) {
        record.alert = record.decrypted.alert;
        record.description = `Alert (${nameAlert(record.alert.level, record.alert.description)})`;
      } else {
        record.description = 'Encrypted Alert';
      }
      return;
    case 24:
      record.description = 'Heartbeat';
      return;
    case CT_HANDSHAKE: {
      if (!body || cursor.encrypted) {
        decryptIfPossible(record, conv, cursor, appFrame);
        record.description = record.decrypted
          ? describeDecrypted(record.decrypted)
          : 'Encrypted Handshake Message';
        return;
      }
      const parts: string[] = [];
      const types: number[] = [];
      for (let p = 0; p + 4 <= body.length;) {
        const type = body[p];
        const len = (body[p + 1] << 16) | (body[p + 2] << 8) | body[p + 3];
        const name = HANDSHAKE_TYPE_NAMES[type];
        if (name === undefined || p + 4 + len > body.length) {
          // Post-ChangeCipherSpec handshake records are ciphertext, so the
          // first byte is not a type - or the record is malformed. Either
          // way nothing after this point in the record can be read.
          if (parts.length === 0) parts.push('Encrypted Handshake Message');
          break;
        }
        types.push(type);
        const msg = body.subarray(p, p + 4 + len);
        if (type === 1) {
          const hello = parseClientHello(msg);
          if (hello) {
            record.hello = hello;
            conv.clientHelloSeen = true;
            conv.clientHelloVersion = hello.version;
            conv.sni = hello.echReal ? undefined : hello.sni ?? undefined;
            conv.clientRandom = hello.random;
            cursor.role = 'client';
            parts.push(hello.sni ? `Client Hello (SNI=${hello.sni})` : 'Client Hello');
          } else parts.push('Client Hello');
        } else if (type === 2) {
          const sh = parseServerHello(msg);
          if (sh) {
            record.serverHello = sh;
            conv.serverHelloSeen = true;
            conv.negotiatedVersion = sh.selectedVersion ?? sh.version;
            if (conv.negotiatedVersion >= 0x0304) conv.encryptedHandshake = true;
            conv.serverRandom = sh.random;
            conv.cipherSuite = sh.cipher;
            if (sh.alpn !== null) conv.alpn = sh.alpn;
            cursor.role = 'server';
            deriveConversationKeys(conv);
          }
          parts.push('Server Hello');
        } else if (type === 11) {
          record.certificates = parseCertificates(msg);
          parts.push('Certificate');
        } else {
          parts.push(name);
        }
        p += 4 + len;
      }
      record.handshakeTypes = types;
      record.description = parts.join(', ');
      return;
    }
    default:
      // A record above the Info ceiling is read and shown in the tree, and says
      // nothing in the column - an empty description is dropped from the join.
      record.description = record.contentType > INFO_NAMED_CONTENT_TYPE_MAX
        ? '' : (CONTENT_TYPE_NAMES[record.contentType] ?? `Unknown (${record.contentType})`);
  }
}

function describeDecrypted(view: DecryptedRecordView): string {
  if (view.app && view.app.info.length > 0) return view.app.info.join(', ');
  if (view.alert) return `Alert (${nameAlert(view.alert.level, view.alert.description)})`;
  if (view.handshake && view.handshake.length > 0) return view.handshake;
  return `Decrypted Application Data (${view.plaintextLength} bytes)`;
}

/** The version a record's row is labelled with. */
function labelVersion(record: TlsRecord, conv: TlsConversationState): number {
  if (record.hello) return record.hello.version;
  if (record.serverHello) return conv.negotiatedVersion ?? record.serverHello.version;
  if (conv.negotiatedVersion !== undefined) return conv.negotiatedVersion;
  // A header accepted on content type alone can carry any two bytes as its
  // version; the row keeps the conversation's last real one.
  return TLS_VERSION_NAMES[record.version] !== undefined ? record.version : (conv.lastRecordVersion ?? 0x0303);
}

// --- the segment ----------------------------------------------------------------

export interface TlsSegmentContext {
  frameId: number;
  /**
   * Capture time, epoch microseconds.
   *
   * Only `http.time` reads it, and only on a connection a key log opened -
   * but without it a decrypted HTTP response is the one place this build
   * could name the request it answers and not say how long it waited.
   */
  tsUs?: number;
  cursor: TlsRecordCursor;
  conversation: TlsConversationState;
  /** False for a retransmitted or out-of-order segment: read what is visible, advance nothing. */
  inOrder: boolean;
  /** The segment's TCP sequence number; records are tracked by sequence, not by count. */
  segmentSeq: number;
  /** True when data before this segment was never captured. */
  gap: boolean;
}

export interface TlsSegmentResult {
  protocolLabel: string;
  info: string;
  fields: Record<string, string | number>;
  layer: ProtocolLayer;
  records: TlsRecord[];
  /** Frames whose Info gets " [TCP PDU reassembled in <frameId>]". */
  reassembledFrom: number[];
  /** Frames whose Protocol label the negotiated version just settled. */
  labelPatches?: { frameId: number; protocolLabel: string }[];
  /**
   * When a key log opened the records and the plaintext was an application
   * protocol this build reads, the Protocol column becomes that protocol -
   * "HTTP2" rather than "TLSv1.3" - because that is what the frame now shows.
   */
  appProtocolLabel?: string;
  /**
   * The decrypted layers, appended after the TLS one. `frameProtocols` is read
   * from the layer names in order, so appending them here is also what puts
   * `http2` under `tls` in the protocol hierarchy.
   */
  appLayers?: ProtocolLayer[];
  /**
   * `frameProtocols` tokens for a certificate this segment carried.
   *
   * The certificate's rows live inside the TLS layer's tree rather than in
   * layers of their own, so there is no layer name for the token to be read
   * off - which is the same position QUIC and SSDP are in, and the same
   * answer. The reference's own chain for a TLS 1.2 Certificate frame reads
   * `...tls:x509sat:x509ce:pkix1implicit:x509ce`, measured on the synthetic
   * handshake in `scripts/tls/certificate.ts`, so without these the barewords
   * `x509af` and `x509ce` would validate as filters and match nothing.
   */
  protocolTokens?: string[];
}

export type TlsSegmentOutcome =
  | { kind: 'tls'; result: TlsSegmentResult }
  /** The segment carried part of a record and completed none: a plain TCP frame for now. */
  | { kind: 'continuation' }
  | { kind: 'none' };

function cloneCursor(c: TlsRecordCursor): TlsRecordCursor {
  return {
    ...c, readOnly: true,
    headerPartial: [...c.headerPartial], contributors: [...c.contributors],
    contributions: [...c.contributions], buffer: c.buffer ? [...c.buffer] : null,
  };
}

function concat(chunks: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let p = 0;
  for (const c of chunks) { out.set(c, p); p += c.length; }
  return out;
}

export function dissectTlsSegment(bytes: Uint8Array, start: number, end: number, ctx: TlsSegmentContext): TlsSegmentOutcome {
  if (end - start <= 0) return { kind: 'none' };
  // An out-of-order segment is read against a throwaway copy so the real
  // cursor - which describes the in-order stream - is not moved by it.
  const cursor = ctx.inOrder ? ctx.cursor : cloneCursor(ctx.cursor);
  const conv = ctx.conversation;
  const frame = ctx.frameId;
  const completed: TlsRecord[] = [];
  let contributed = false;
  let p = start;

  const completeSpanning = (): void => {
    // A record with a hole in it does not complete as a record.
    //
    // Reaching its end sequence means the direction can resynchronise here, and
    // nothing more: part of the body was never captured, so there is no record
    // to show and no frame to credit. Emitting nothing is what the reference
    // does - it prints the plain TCP summary on the frame that would have
    // finished the record, and on every segment that fed it.
    //
    // Getting this wrong is not a missing tag, it is an invented one. Carrying
    // a record across an unfilled hole tagged thirty consecutive bulk frames
    // `[TCP PDU reassembled in 1450]` for a PDU that never existed, and
    // consumed the bytes that would have resynchronised the direction, so the
    // error propagated well past the frames that showed it.
    if (!cursor.holed) {
      const body = cursor.buffer ? concat(cursor.buffer, cursor.bufferedBytes) : null;
      completed.push({
        contentType: cursor.contentType, version: cursor.version, length: cursor.recordLength,
        body, reassembledFrom: [...cursor.contributors], contributions: [...cursor.contributions], description: '',
      });
    }
    cursor.remaining = 0; cursor.contributors = []; cursor.contributions = []; cursor.buffer = null; cursor.bufferedBytes = 0;
    cursor.holed = false;
  };

  const startSpanning = (h: RecordHeader, bodyStart: number): void => {
    const avail = end - bodyStart;
    cursor.contentType = h.contentType; cursor.version = h.version; cursor.recordLength = h.length;
    cursor.remaining = h.length - avail;
    cursor.recordEndSeq = (ctx.segmentSeq + (bodyStart - start) + h.length) >>> 0;
    cursor.contributions = [{ frame, bytes: avail }];
    cursor.contributors = [];
    // A new record inherits nothing from the one that went before it.
    cursor.holed = false;
    // Handshake records are always buffered, because a hello can outgrow a
    // segment; application data is buffered only once a key log has opened the
    // conversation, since holding every record of every TLS stream would cost
    // the buffer's whole memory budget to no purpose.
    const wantBody = h.contentType === CT_HANDSHAKE
      || (conv.keys != null && h.contentType !== CT_CHANGE_CIPHER_SPEC);
    if (wantBody && h.length <= MAX_BUFFERED_RECORD) {
      cursor.buffer = [bytes.slice(bodyStart, end)];
      cursor.bufferedBytes = avail;
    } else {
      cursor.buffer = null; cursor.bufferedBytes = 0;
    }
    contributed = true;
  };

  // 1. A record header that straddled the previous boundary.
  if (cursor.headerPartial.length > 0) {
    const need = 5 - cursor.headerPartial.length;
    const take = Math.min(need, end - p);
    for (let i = 0; i < take; i++) cursor.headerPartial.push(bytes[p + i]);
    p += take;
    if (cursor.headerPartial.length < 5) {
      cursor.contributions.push({ frame, bytes: take });
      cursor.contributors.push(frame);
      return { kind: 'continuation' };
    }
    const h = headerFromPartial(cursor.headerPartial);
    const carried = cursor.contributions;
    const carriedFrames = cursor.contributors;
    cursor.headerPartial = [];
    if (h === null) {
      cursor.unknown = true; cursor.remaining = 0; cursor.contributions = []; cursor.contributors = [];
    } else if (end - p >= h.length) {
      completed.push({
        contentType: h.contentType, version: h.version, length: h.length,
        body: bytes.subarray(p, p + h.length), reassembledFrom: [...carriedFrames],
        contributions: [...carried, { frame, bytes: h.length }], description: '',
      });
      cursor.contributions = []; cursor.contributors = [];
      p += h.length;
    } else {
      startSpanning(h, p);
      cursor.contributions.unshift(...carried);
      cursor.contributors.unshift(...carriedFrames);
      p = end;
    }
  }

  // A lost segment inside a record: the record's end is a sequence number,
  // which the gap did not move, so what this segment owes it is recomputed
  // from that rather than from the bytes counted so far. A gap that swallowed
  // the record's end leaves nothing to complete; the direction starts over.
  // The same rule a payload-less segment reporting the same gap applies, and
  // deliberately the same function: the two paths disagreeing is how a record
  // came to survive a 671 kB hole on one and not the other.
  if (ctx.gap) applyGapToCursor(cursor, ctx.segmentSeq);

  // 2. The record in progress from earlier segments.
  if (cursor.remaining > 0 && p < end) {
    const take = Math.min(cursor.remaining, end - p);
    if (cursor.buffer) { cursor.buffer.push(bytes.slice(p, p + take)); cursor.bufferedBytes += take; }
    cursor.contributions.push({ frame, bytes: take });
    cursor.remaining -= take;
    p += take;
    if (cursor.remaining > 0) {
      cursor.contributors.push(frame);
      return { kind: 'continuation' };
    }
    completeSpanning();
  }

  // 3. Records that begin in this segment.
  while (p < end) {
    if (end - p < 5) {
      if (completed.length === 0 && cursor.unknown) break; // a few stray bytes on an unknown stream
      const ct = bytes[p];
      if (ct < CT_CHANGE_CIPHER_SPEC || ct > 24) {
        // Not the start of a header, however short: Wireshark decides on the
        // content-type byte before it asks for more bytes.
        if (completed.length > 0) {
          completed.push({
            contentType: 0, version: 0, length: end - p, body: null, reassembledFrom: [], contributions: [],
            description: 'Ignored Unknown Record', ignored: true, range: [p, end - 1],
          });
          break;
        }
        return { kind: 'tls', result: ignoredUnknownRecord(conv, frame) };
      }
      cursor.headerPartial = Array.from(bytes.subarray(p, end));
      cursor.contributions = [{ frame, bytes: end - p }];
      cursor.contributors = completed.length === 0 ? [frame] : [];
      contributed = completed.length === 0;
      p = end;
      break;
    }
    const h = readRecordHeader(bytes, p, cursor.unknown);
    if (h === null) {
      if (completed.length > 0) {
        // Trailing bytes that begin no record: named, and the segment consumed.
        completed.push({
          contentType: 0, version: 0, length: end - p, body: null, reassembledFrom: [], contributions: [],
          description: 'Ignored Unknown Record', ignored: true, range: [p, end - 1],
        });
        break;
      }
      if (completed.length === 0) {
        // Not a record boundary. On a direction that has never shown a record
        // (a capture that started mid-connection) this is just TCP. On one
        // that has, Wireshark keeps the TLS label, calls the segment
        // "Ignored Unknown Record", swallows it whole, and looks for a header
        // again at the start of the next segment - which is how a stream
        // resynchronises after a loss ate a record header.
        if (cursor.unknown) return { kind: 'none' };
        return { kind: 'tls', result: ignoredUnknownRecord(conv, frame) };
      }
      break;
    }
    cursor.unknown = false;
    const bodyStart = p + 5;
    if (end - bodyStart >= h.length) {
      completed.push({
        contentType: h.contentType, version: h.version, length: h.length,
        body: bytes.subarray(bodyStart, bodyStart + h.length), range: [p, bodyStart + h.length - 1],
        reassembledFrom: [], contributions: [], description: '',
      });
      p = bodyStart + h.length;
    } else {
      startSpanning(h, bodyStart);
      // A frame that completed a record is shown as that record, so it is not
      // also listed among the next record's reassembled segments - matching
      // how Wireshark attributes a frame to the PDU it finishes.
      if (completed.length === 0) cursor.contributors = [frame];
      p = end;
    }
  }

  if (completed.length === 0) {
    return contributed ? { kind: 'continuation' } : { kind: 'none' };
  }

  const appFrame = ctx.tsUs !== undefined ? { id: ctx.frameId, tsUs: ctx.tsUs } : undefined;
  for (const r of completed) describeRecord(r, conv, cursor, appFrame);

  const fields: Record<string, string | number> = {};
  const first = completed[0];
  fields['tls.record.content_type'] = first.contentType;
  fields['tls.record.version'] = first.version;
  fields['tls.record.length'] = first.length;
  const reassembledFrom: number[] = [];
  for (const r of completed) {
    for (const f of r.reassembledFrom) if (!reassembledFrom.includes(f)) reassembledFrom.push(f);
    if (r.handshakeTypes && r.handshakeTypes.length > 0) fields['tls.handshake.type'] = r.handshakeTypes[0];
    if (r.hello) {
      const h = r.hello;
      fields['tls.handshake.version'] = h.version;
      if (h.sni !== null) fields['tls.handshake.extensions_server_name'] = h.sni;
      if (h.alpn.length > 0) fields['tls.handshake.extensions_alpn_str'] = h.alpn.join(',');
      if (h.supportedVersions.length > 0) fields['tls.handshake.extensions.supported_version'] = Math.max(...h.supportedVersions.filter((v) => !isGrease(v)));
      if (h.groups.length > 0) fields['tls.handshake.extensions_supported_group'] = h.groups.find((g) => !isGrease(g)) ?? h.groups[0];
      if (h.keyShares.length > 0) fields['tls.handshake.extensions_key_share_group'] = h.keyShares.find((k) => !isGrease(k.group))?.group ?? h.keyShares[0].group;
      fields['tls.handshake.extensions_ech'] = h.echPresent ? 1 : 0;
      fields['tls.handshake.ja3'] = h.ja3;
      fields['tls.handshake.ja3_full'] = h.ja3Full;
      fields['tls.handshake.ja4'] = h.ja4;
      fields['tls.handshake.ja4_r'] = h.ja4Raw;
    }
    if (r.serverHello) {
      const s = r.serverHello;
      fields['tls.handshake.version'] = s.version;
      fields['tls.handshake.ciphersuite'] = s.cipher;
      if (s.selectedVersion !== null) fields['tls.handshake.extensions.supported_version'] = s.selectedVersion;
      if (s.keyShareGroup !== null) fields['tls.handshake.extensions_key_share_group'] = s.keyShareGroup;
      if (s.alpn !== null) fields['tls.handshake.extensions_alpn_str'] = s.alpn;
      fields['tls.handshake.ja3s'] = s.ja3s;
      fields['tls.handshake.ja3s_full'] = s.ja3sFull;
    }
    if (r.certificates && r.certificates.length > 0) {
      const leaf = r.certificates[0];
      if (leaf.subjectCN) fields['tls.x509.subject_cn'] = leaf.subjectCN;
      if (leaf.issuerCN) fields['tls.x509.issuer_cn'] = leaf.issuerCN;
    }
    if (r.alert) {
      fields['tls.alert_message.level'] = r.alert.level;
      fields['tls.alert_message.desc'] = r.alert.description;
    }
  }
  if (reassembledFrom.length > 0) fields['tls.reassembled'] = 1;

  const last = completed[completed.length - 1];
  const protocolLabel = nameVersion(labelVersion(last, conv));
  // A record that describes itself as nothing is omitted rather than joined as
  // an empty element, which would leave a leading ", " in front of the next.
  const info = completed.map((r) => r.description).filter((d) => d !== '').join(', ');
  const layer = buildTlsLayer(completed, conv, frame);

  // What the decryption produced, gathered across the frame's records.
  let appProtocolLabel: string | undefined;
  let appLayers: ProtocolLayer[] | undefined;
  for (const r of completed) {
    const app = r.decrypted?.app;
    if (!app || app.protocolLabel === null) continue;
    appProtocolLabel = app.protocolLabel;
    appLayers = [...(appLayers ?? []), ...app.layers];
    for (const [key, value] of Object.entries(app.fields)) fields[key] = value;
  }
  if (completed.some((r) => r.decrypted !== undefined)) fields['inwire.tls.decrypted'] = 1;
  for (const r of completed) {
    const certificates = r.decrypted?.certificates;
    if (certificates && certificates.length > 0) {
      if (certificates[0].subjectCN) fields['tls.x509.subject_cn'] = certificates[0].subjectCN;
      if (certificates[0].issuerCN) fields['tls.x509.issuer_cn'] = certificates[0].issuerCN;
    }
  }

  // Frames labelled before the server answered are re-labelled with what was
  // negotiated - Wireshark's two-pass view shows a TLS 1.3 conversation's
  // ClientHello as TLSv1.3, and this is the single-pass way to match it.
  let labelPatches: { frameId: number; protocolLabel: string }[] | undefined;
  const settledNow = completed.some((r) => r.serverHello !== undefined);
  if (settledNow && conv.negotiatedVersion !== undefined) {
    const negotiated = nameVersion(conv.negotiatedVersion);
    labelPatches = conv.pendingVersionFrames.filter((f) => f !== frame).map((frameId) => ({ frameId, protocolLabel: negotiated }));
    conv.pendingVersionFrames = [];
    if (labelPatches.length === 0) labelPatches = undefined;
  } else if (conv.negotiatedVersion === undefined && ctx.inOrder) {
    if (!conv.pendingVersionFrames.includes(frame)) conv.pendingVersionFrames.push(frame);
  }
  // The tokens for a certificate this segment carried. `pkix1implicit` only
  // when an access description was actually read, because a token for a frame
  // that has none is a protocol claimed on no evidence.
  const certificates = completed.flatMap((r) => r.certificates ?? r.decrypted?.certificates ?? []);
  const protocolTokens = certificates.length > 0
    ? ['x509af', 'x509ce', ...(certificates.some((c) => c.accessDescriptions.length > 0) ? ['pkix1implicit'] : [])]
    : undefined;

  return {
    kind: 'tls',
    result: {
      protocolLabel, info, fields, layer, records: completed, reassembledFrom, labelPatches,
      appProtocolLabel, appLayers, protocolTokens,
    },
  };
}

function ignoredUnknownRecord(conv: TlsConversationState, frame: number): TlsSegmentResult {
  const protocolLabel = nameVersion(conv.negotiatedVersion ?? 0x0303);
  return {
    protocolLabel,
    info: 'Ignored Unknown Record',
    fields: {},
    layer: {
      name: 'Transport Layer Security',
      summary: `Transport Layer Security (${protocolLabel}) - frame ${frame}`,
      fields: [{
        name: `${protocolLabel} Record Layer: Ignored Unknown Record`,
        value: '',
        children: [{
          name: '[Note]', generated: true,
          value: 'This segment does not start at a record boundary and no record was in progress - usually the header was in a lost segment. The stream resynchronises at the next segment that begins with a valid record header.',
        }],
      }],
    },
    records: [],
    reassembledFrom: [],
  };
}

// --- the tree ----------------------------------------------------------------------

const hexField = (name: string, value: Uint8Array, range?: [number, number]): ProtocolField =>
  ({ name, value: toHex(value), ...(range ? { rawBytesRange: range } : {}) });

function versionField(name: string, v: number, abbrev: string): ProtocolField {
  return { name, value: `${TLS_VERSION_NAMES[v]?.replace('TLSv', 'TLS ') ?? 'Unknown'} (0x${hex4(v)})`, abbrev };
}

function extensionFields(ext: Extension): ProtocolField[] {
  const b = ext.body;
  const children: ProtocolField[] = [
    { name: 'Type', value: nameExtension(ext.type) },
    { name: 'Length', value: b.length },
  ];
  switch (ext.type) {
    case 0: {
      const sni = parseSni(b);
      if (sni !== null) children.push({ name: 'Server Name', value: sni, abbrev: 'tls.handshake.extensions_server_name' });
      break;
    }
    case 16:
      for (const proto of parseAlpn(b)) children.push({ name: 'ALPN Next Protocol', value: proto, abbrev: 'tls.handshake.extensions_alpn_str' });
      break;
    case 43:
      if (b.length >= 2 && b.length === 2) {
        children.push({ name: 'Supported Version', value: nameVersion(u16(b, 0)), abbrev: 'tls.handshake.extensions.supported_version' });
      } else {
        for (const v of u16List(b, 1)) children.push({ name: 'Supported Version', value: nameVersion(v), abbrev: 'tls.handshake.extensions.supported_version' });
      }
      break;
    case 10:
      for (const g of u16List(b, 2)) children.push({ name: 'Supported Group', value: nameGroup(g), abbrev: 'tls.handshake.extensions_supported_group' });
      break;
    case 11:
      if (b.length >= 1) for (const f of Array.from(b.subarray(1, 1 + b[0]))) children.push({ name: 'EC point format', value: `${EC_POINT_FORMAT_NAMES[f] ?? 'Unknown'} (${f})` });
      break;
    case 13:
      for (const s of u16List(b, 2)) children.push({ name: 'Signature Algorithm', value: nameSignatureAlgorithm(s) });
      break;
    case 45:
      if (b.length >= 1) for (const m of Array.from(b.subarray(1, 1 + b[0]))) children.push({ name: 'PSK Key Exchange Mode', value: `${PSK_KEY_EXCHANGE_MODE_NAMES[m] ?? 'Unknown'} (${m})` });
      break;
    case 51: {
      if (b.length < 2) break;
      // ClientHello carries a list with a 2-byte length; ServerHello carries one entry.
      const total = u16(b, 0);
      const list = total + 2 === b.length || total + 2 <= b.length;
      let q = list ? 2 : 0;
      if (!list) q = 0;
      const stop = list ? Math.min(b.length, 2 + total) : b.length;
      while (q + 4 <= stop) {
        const group = u16(b, q);
        const len = u16(b, q + 2);
        children.push({
          name: 'Key Share Entry',
          value: `Group: ${nameGroup(group)}, Key Exchange length: ${len}`,
          abbrev: 'tls.handshake.extensions_key_share_group',
          ...(len >= 1000 ? { description: 'A share this large is a post-quantum (ML-KEM / Kyber) key.' } : {}),
        });
        q += 4 + len;
      }
      break;
    }
    case 0xfe0d:
      children.push({ name: 'Note', value: b.length <= 1 ? 'GREASE (outer)' : `${b.length} bytes - real or GREASE; see the SNI heuristic`, generated: true });
      break;
  }
  return children;
}

function helloFields(h: HelloFacts): ProtocolField[] {
  const fields: ProtocolField[] = [
    versionField('Version', h.version, 'tls.handshake.version'),
    hexField('Random', h.random),
    { name: 'Session ID Length', value: h.sessionId.length },
    ...(h.sessionId.length > 0 ? [hexField('Session ID', h.sessionId)] : []),
    { name: 'Cipher Suites Length', value: h.ciphers.length * 2 },
    {
      name: `Cipher Suites (${h.ciphers.length} suites)`,
      value: '',
      children: h.ciphers.map((c) => ({ name: 'Cipher Suite', value: nameCipher(c), abbrev: 'tls.handshake.ciphersuite' })),
    },
    { name: 'Compression Methods Length', value: h.compression.length },
    { name: 'Compression Methods', value: h.compression.map((c) => (c === 0 ? 'null (0)' : String(c))).join(', ') },
    { name: 'Extensions Length', value: h.extensions.reduce((n, e) => n + 4 + e.body.length, 0) },
    ...h.extensions.map((e): ProtocolField => ({
      name: `Extension: ${nameExtension(e.type).replace(/ \(\d+\)$/, '')} (len=${e.body.length})`,
      value: '',
      children: extensionFields(e),
    })),
    { name: '[JA3 Fullstring]', value: h.ja3Full, generated: true, abbrev: 'tls.handshake.ja3_full' },
    { name: '[JA3]', value: h.ja3, generated: true, abbrev: 'tls.handshake.ja3' },
    { name: '[JA4]', value: h.ja4, generated: true, abbrev: 'tls.handshake.ja4' },
    { name: '[JA4_r]', value: h.ja4Raw, generated: true, abbrev: 'tls.handshake.ja4_r' },
  ];
  if (h.echPresent) {
    fields.push({
      name: '[Encrypted Client Hello]',
      value: h.echReal
        ? `outer SNI ${h.sni} - the real server name is encrypted`
        : 'extension present, GREASE by the outer-name heuristic (Chrome and Firefox send one on every hello)',
      generated: true, abbrev: 'tls.handshake.extensions_ech',
    });
  }
  if (h.hasPreSharedKey) fields.push({ name: '[Session resumption]', value: 'pre_shared_key offered', generated: true });
  return fields;
}

function serverHelloFields(s: ServerHelloFacts, conv: TlsConversationState): ProtocolField[] {
  const fields: ProtocolField[] = [
    versionField('Version', s.version, 'tls.handshake.version'),
    hexField('Random', s.random),
    { name: 'Session ID Length', value: s.sessionId.length },
    ...(s.sessionId.length > 0 ? [hexField('Session ID', s.sessionId)] : []),
    { name: 'Cipher Suite', value: nameCipher(s.cipher), abbrev: 'tls.handshake.ciphersuite' },
    { name: 'Compression Method', value: s.compression === 0 ? 'null (0)' : String(s.compression) },
    ...s.extensions.map((e): ProtocolField => ({
      name: `Extension: ${nameExtension(e.type).replace(/ \(\d+\)$/, '')} (len=${e.body.length})`,
      value: '',
      children: extensionFields(e),
    })),
    { name: '[JA3S Fullstring]', value: s.ja3sFull, generated: true, abbrev: 'tls.handshake.ja3s_full' },
    { name: '[JA3S]', value: s.ja3s, generated: true, abbrev: 'tls.handshake.ja3s' },
  ];
  if ((conv.negotiatedVersion ?? 0) >= 0x0304) {
    fields.push({ name: '[Certificate]', value: 'encrypted (TLS 1.3) - sent inside the encrypted handshake, not absent', generated: true });
  }
  return fields;
}

/**
 * One certificate's rows, under the reference's own field names.
 *
 * `x509af.*`, `x509ce.*` and `pkix1implicit.*` rather than names of ours,
 * because the reference genuinely has them and they are what a filter learnt
 * in Wireshark spells - see `fieldRegistry.ts`, where the three layer tokens
 * are added. The two that stay ours are `tls.x509.subject_cn` and
 * `tls.x509.issuer_cn`: the reference reaches a CN through its generated
 * `x509sat.*` tree, where one `uTF8String` row is every attribute of every
 * name in the chain and nothing says which is the subject's. Those two are
 * exempt in `wireshark-abbrevs.ts` and have been since before this.
 *
 * **Every row here is tree-only.** A chain is two to four certificates, each
 * with several names, usages and access descriptions, so putting them in the
 * per-frame bag would be dozens of keys on a frame - against a tree that is
 * built on demand and thrown away with the pane (ADR 0007). The two CN fields
 * stay in the bag because they are the two anybody filters on.
 */
function certificateFields(certs: CertificateSummary[], conv: TlsConversationState, now: Date): ProtocolField[] {
  return certs.map((c, i): ProtocolField => {
    const children: ProtocolField[] = [
      ...(c.version !== null ? [{ name: 'version', value: c.version, abbrev: 'x509af.version' }] : []),
      ...(c.serialHex ? [{ name: 'serialNumber', value: c.serialHex, abbrev: 'x509af.serialNumber' }] : []),
      ...(c.signatureAlgorithm ? [{ name: 'signature', value: c.signatureAlgorithm, abbrev: 'x509af.algorithm.id' }] : []),
      { name: 'Subject', value: c.subject || '(none)', ...(c.subjectCN ? { abbrev: 'tls.x509.subject_cn' } : {}) },
      { name: 'Issuer', value: c.issuer || '(none)', ...(c.issuerCN ? { abbrev: 'tls.x509.issuer_cn' } : {}) },
      { name: 'Not Before', value: c.notBefore ? c.notBefore.toISOString() : 'unknown' },
      { name: 'Not After', value: c.notAfter ? c.notAfter.toISOString() : 'unknown' },
      // One row per name, as the reference emits one field per name, rather
      // than the joined string this used to draw - which could not say which
      // of them was a DNS name and dropped every other form on the floor.
      ...c.dnsNames.map((n): ProtocolField => ({ name: 'dNSName', value: n, abbrev: 'x509ce.dNSName' })),
      ...c.ipNames.map((n): ProtocolField => ({
        name: 'iPAddress', value: n,
        abbrev: n.includes(':') ? 'x509ce.IPAddress.ipv6' : 'x509ce.IPAddress.ipv4',
      })),
      ...c.emailNames.map((n): ProtocolField => ({ name: 'rfc822Name', value: n, abbrev: 'x509ce.rfc822Name' })),
      ...c.uriNames.map((n): ProtocolField => ({ name: 'uniformResourceIdentifier', value: n, abbrev: 'x509ce.uniformResourceIdentifier' })),
      ...(c.keyType ? [{
        name: 'Public Key Algorithm',
        // The size is the number anybody judges a key by, and it needed the
        // SPKI BIT STRING opened rather than its algorithm read off the front.
        value: c.keyBits !== null ? `${c.keyType} (${c.keyBits} bits)` : c.keyType,
      }] : []),
      // The key SIZE is display-only, and deliberately. The reference's
      // `x509af.subjectPublicKey` is FT_BYTES - the key itself - so a row
      // carrying 2048 under that name would be a filter that works here and
      // nowhere else, which is the exact failure `wireshark-abbrevs.ts`
      // exists to catch. It is in the algorithm row's text instead.
      ...(c.isCa !== null ? [{ name: 'cA', value: c.isCa, abbrev: 'x509ce.cA' }] : []),
      ...(c.pathLen !== null ? [{ name: 'pathLenConstraint', value: c.pathLen, abbrev: 'x509ce.pathLenConstraint' }] : []),
      ...(c.keyUsageHex !== null ? [{
        name: 'KeyUsage',
        value: `${c.keyUsageHex} (${c.keyUsage.join(', ') || 'none'})`,
        abbrev: 'x509ce.KeyUsage',
      }] : []),
      ...c.extKeyUsage.map((p): ProtocolField => ({ name: 'KeyPurposeId', value: p, abbrev: 'x509ce.KeyPurposeId' })),
      ...c.accessDescriptions.map((a): ProtocolField => ({
        name: 'accessMethod',
        value: a.method,
        abbrev: 'pkix1implicit.accessMethod',
        children: [{ name: 'accessLocation', value: a.location, abbrev: 'x509ce.uniformResourceIdentifier' }],
      })),
      ...c.crlDistributionPoints.map((u): ProtocolField => ({
        // One name for every URI in the certificate is the reference's own
        // choice, confirmed on the synthetic capture: the SAN's URI, both
        // access locations and this all come back under it.
        name: 'cRLDistributionPoint', value: u, abbrev: 'x509ce.uniformResourceIdentifier',
      })),
      ...(c.extensions.length > 0 ? [{
        name: 'extensions',
        value: `${c.extensions.length} extension${c.extensions.length === 1 ? '' : 's'}`,
        children: c.extensions.map((e): ProtocolField => ({
          name: 'extnId',
          value: e.critical ? `${e.name} (critical)` : e.name,
          abbrev: 'x509af.extension.id',
          children: [{ name: 'critical', value: e.critical, abbrev: 'x509af.critical' }],
        })),
      }] : []),
    ];
    if (c.notAfter && c.notAfter < now) children.push({ name: '[Expert]', value: 'certificate has expired', generated: true, expertInfo: { category: 'Security', message: 'Certificate expired' } });
    if (c.selfSigned) children.push({ name: '[Expert]', value: 'self-signed certificate', generated: true, expertInfo: { category: 'Security', message: 'Self-signed certificate' } });
    if (i === 0 && conv.sni && c.subjectCN && !c.dnsNames.includes(conv.sni) && c.subjectCN !== conv.sni
      && !c.dnsNames.some((n) => n.startsWith('*.') && conv.sni!.endsWith(n.slice(1)))) {
      children.push({ name: '[Expert]', value: `name mismatch: SNI ${conv.sni} is not in this certificate`, generated: true, expertInfo: { category: 'Security', message: 'Certificate name does not match SNI' } });
    }
    return { name: i === 0 ? `Certificate (leaf): ${c.subjectCN ?? c.subject}` : `Certificate: ${c.subjectCN ?? c.subject}`, value: '', children };
  });
}

function buildTlsLayer(records: TlsRecord[], conv: TlsConversationState, frame: number, now: Date = new Date()): ProtocolLayer {
  const fields: ProtocolField[] = [];
  for (const r of records) {
    if (r.ignored) {
      fields.push({
        name: 'Ignored Unknown Record', value: `${r.length} bytes`, ...(r.range ? { rawBytesRange: r.range } : {}),
        expertInfo: { category: 'Broken', message: 'Ignored Unknown Record' },
      });
      continue;
    }
    const versionName = nameVersion(labelVersion(r, conv));
    const children: ProtocolField[] = [
      { name: 'Content Type', value: `${CONTENT_TYPE_NAMES[r.contentType] ?? 'Unknown'} (${r.contentType})`, abbrev: 'tls.record.content_type',
        ...(r.range ? { rawBytesRange: [r.range[0], r.range[0]] as [number, number] } : {}) },
      versionField('Version', r.version, 'tls.record.version'),
      { name: 'Length', value: r.length, abbrev: 'tls.record.length' },
    ];
    if (r.contentType === CT_HANDSHAKE && r.body && !cursorEncrypted(r)) {
      const body = r.body;
      for (let p = 0; p + 4 <= body.length;) {
        const type = body[p];
        const len = (body[p + 1] << 16) | (body[p + 2] << 8) | body[p + 3];
        const name = HANDSHAKE_TYPE_NAMES[type];
        if (name === undefined || p + 4 + len > body.length) break;
        const hs: ProtocolField = {
          name: `Handshake Protocol: ${name}`,
          value: '',
          children: [
            { name: 'Handshake Type', value: `${name} (${type})`, abbrev: 'tls.handshake.type' },
            { name: 'Length', value: len },
          ],
        };
        if (type === 1 && r.hello) hs.children!.push(...helloFields(r.hello));
        else if (type === 2 && r.serverHello) hs.children!.push(...serverHelloFields(r.serverHello, conv));
        else if (type === 11 && r.certificates) hs.children!.push(...certificateFields(r.certificates, conv, now));
        children.push(hs);
        p += 4 + len;
      }
    } else if (r.contentType === CT_ALERT && r.alert) {
      children.push(
        { name: 'Level', value: `${ALERT_LEVEL_NAMES[r.alert.level] ?? 'Unknown'} (${r.alert.level})`, abbrev: 'tls.alert_message.level' },
        { name: 'Description', value: `${ALERT_DESCRIPTION_NAMES[r.alert.description] ?? 'Unknown'} (${r.alert.description})`, abbrev: 'tls.alert_message.desc' },
      );
    } else if (r.contentType === CT_APPLICATION_DATA && r.range && r.decrypted === undefined) {
      children.push({ name: 'Encrypted Application Data', value: `${r.length} bytes`, rawBytesRange: [r.range[0] + 5, r.range[1]] });
    }
    if (r.decrypted) children.push(...decryptedFields(r.decrypted, conv, now));
    else if (conv.keyNote !== undefined && r.contentType === CT_APPLICATION_DATA) {
      children.push({ name: '[Not decrypted]', value: conv.keyNote, generated: true });
    }
    if (r.reassembledFrom.length > 0) {
      const parts = r.contributions.map((c) => `#${c.frame}(${c.bytes})`).join(', ');
      children.push({
        name: `[Reassembled TCP segments (${r.length} bytes)]`, value: parts, generated: true, abbrev: 'tls.reassembled',
      });
    }
    fields.push({
      name: `${versionName} Record Layer: ${recordTitle(r)}`,
      value: '',
      ...(r.range ? { rawBytesRange: r.range } : {}),
      children,
    });
  }
  const summaryVersion = records.length > 0 ? nameVersion(labelVersion(records[records.length - 1], conv)) : 'TLS';
  return { name: 'Transport Layer Security', summary: `Transport Layer Security (${summaryVersion}) - frame ${frame}`, fields };
}

/**
 * The rows a decrypted record adds.
 *
 * None of them carry a byte range: they describe bytes that are not in this
 * frame's hex dump in the form shown, which is the same rule a layer built
 * from a reassembled TCP or IP payload follows.
 */
function decryptedFields(view: DecryptedRecordView, conv: TlsConversationState, now: Date): ProtocolField[] {
  const children: ProtocolField[] = [
    { name: 'Content Type', value: `${CONTENT_TYPE_NAMES[view.contentType] ?? 'Unknown'} (${view.contentType})` },
    { name: 'Length', value: view.plaintextLength },
    { name: 'Keys', value: `${view.epoch} traffic secret, from the key log`, generated: true },
  ];
  if (view.handshake) children.push({ name: 'Handshake', value: view.handshake });
  if (view.certificates && view.certificates.length > 0) {
    children.push(...certificateFields(view.certificates, conv, now));
  }
  if (view.alert) {
    children.push(
      { name: 'Level', value: `${ALERT_LEVEL_NAMES[view.alert.level] ?? 'Unknown'} (${view.alert.level})` },
      { name: 'Description', value: `${ALERT_DESCRIPTION_NAMES[view.alert.description] ?? 'Unknown'} (${view.alert.description})` },
    );
  }
  return [{ name: '[Decrypted TLS record]', value: '', generated: true, isExpanded: true, children }];
}

/**
 * The TLS layer for a handshake carried in QUIC CRYPTO frames.
 *
 * QUIC has no TLS record layer - the handshake messages are the stream - so
 * this builds the same hello subtrees `buildTlsLayer` does without the record
 * wrapper around them.
 */
export function buildQuicTlsLayer(hello?: HelloFacts, serverHello?: ServerHelloFacts): ProtocolLayer {
  const conv: TlsConversationState = {
    clientHelloSeen: hello !== undefined,
    serverHelloSeen: serverHello !== undefined,
    encryptedHandshake: false,
    pendingVersionFrames: [],
    negotiatedVersion: serverHello?.selectedVersion ?? undefined,
  };
  const fields: ProtocolField[] = [];
  if (hello) {
    fields.push({
      name: 'Handshake Protocol: Client Hello', value: '',
      children: [{ name: 'Handshake Type', value: 'Client Hello (1)', abbrev: 'tls.handshake.type' }, ...helloFields(hello)],
    });
  }
  if (serverHello) {
    fields.push({
      name: 'Handshake Protocol: Server Hello', value: '',
      children: [{ name: 'Handshake Type', value: 'Server Hello (2)', abbrev: 'tls.handshake.type' }, ...serverHelloFields(serverHello, conv)],
    });
  }
  return { name: 'Transport Layer Security', summary: 'Transport Layer Security (QUIC handshake)', fields };
}

function cursorEncrypted(r: TlsRecord): boolean {
  return r.description === 'Encrypted Handshake Message';
}

function recordTitle(r: TlsRecord): string {
  switch (r.contentType) {
    case CT_HANDSHAKE: return `Handshake Protocol: ${r.description}`;
    case CT_APPLICATION_DATA:
      return r.decrypted
        ? `Application Data Protocol: ${r.description}`
        : 'Application Data Protocol: Application Data';
    case CT_ALERT: return r.alert ? `Alert (${ALERT_LEVEL_NAMES[r.alert.level] ?? 'Unknown'}): ${ALERT_DESCRIPTION_NAMES[r.alert.description] ?? 'Unknown'}` : 'Encrypted Alert';
    case CT_CHANGE_CIPHER_SPEC: return 'Change Cipher Spec Protocol: Change Cipher Spec';
    default: return r.description;
  }
}
