/**
 * A TLS 1.2 handshake with a certificate in it, which neither fixture has.
 *
 *   npx tsx scripts/tls/certificate.ts
 *
 * **This is the oracle P5 could not be done without.** Both parity captures
 * negotiate TLS 1.3, which encrypts the Certificate message - so tshark emits
 * no `x509af.*`, `x509ce.*` or `x509sat.*` on either of them either, and
 * `tree-coverage.ts` has nothing to compare. `scripts/tls/dissect.ts` records
 * the same gap in its own header: *"no TLS 1.2 handshake exists in either
 * fixture to lift one from, which is also why tshark cannot cross-check it"*.
 *
 * So the handshake is built here, and the certificate with it.
 *
 * ## Why the certificate is authored rather than pasted
 *
 * `scripts/tls/dissect.ts` carries one as six lines of hex from `openssl req
 * -x509`. That is fine for what it asserts - a subject, two names and a date -
 * and it is the wrong shape for this, because the fields under test are the
 * ones an `openssl req` one-liner does not emit: key usage, extended key
 * usage, basic constraints, authority information access, CRL distribution
 * points, and a subjectAltName carrying something other than a dNSName.
 *
 * A hex blob also hides what it contains. Built from `der()` below, the
 * certificate reads as RFC 5280 §4.1's own ASN.1 - which is the rule
 * `scripts/parity/synthetic.ts` states for frames and holds just as well for a
 * structure: *"every field is written explicitly, so a test frame reads as the
 * RFC's packet diagram rather than as a call to a helper that might be wrong
 * in the same way the dissector is"*.
 *
 * The signature is 256 bytes of nothing. Nothing verifies it - not this build,
 * not tshark - and a real one would need a key, which would need either a
 * dependency or a committed secret to sign with.
 */
import { useRepositoryWiresharkProfile } from '../wiresharkProfile';
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

// --- DER ----------------------------------------------------------------------

/** One TLV: a tag, a definite length in the short or long form, and content. */
function der(tag: number, content: number[]): number[] {
  const length = content.length;
  if (length < 0x80) return [tag, length, ...content];
  const bytes: number[] = [];
  for (let v = length; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
  return [tag, 0x80 | bytes.length, ...bytes, ...content];
}

const seq = (...parts: number[][]): number[] => der(0x30, parts.flat());
const set = (...parts: number[][]): number[] => der(0x31, parts.flat());
const bool = (v: boolean): number[] => der(0x01, [v ? 0xff : 0x00]);
const nullTag = (): number[] => der(0x05, []);
/** An explicit [n] wrapper, which is how the optional certificate fields are tagged. */
const explicit = (n: number, ...parts: number[][]): number[] => der(0xa0 | n, parts.flat());
/** An implicit [n] primitive, which is how a GeneralName carries its value. */
const implicit = (n: number, content: number[]): number[] => der(0x80 | n, content);
const ascii = (tag: number, text: string): number[] => der(tag, [...text].map((c) => c.charCodeAt(0)));
const utf8String = (text: string) => ascii(0x0c, text);
const utcTime = (text: string) => ascii(0x17, text);

/** A positive INTEGER, with the leading zero DER requires when bit 7 is set. */
function integer(bytes: number[]): number[] {
  return der(0x02, bytes[0] & 0x80 ? [0x00, ...bytes] : bytes);
}

/** A BIT STRING with no unused trailing bits, unless `unused` says otherwise. */
function bitString(content: number[], unused = 0): number[] {
  return der(0x03, [unused, ...content]);
}

const octetString = (content: number[]): number[] => der(0x04, content);

/**
 * An OBJECT IDENTIFIER from dotted form.
 *
 * The first two arcs share a byte as `40 * x + y`, and every arc after is
 * base-128 with the continuation bit set on all but the last - the same rule
 * `decodeOid` in `dissectors/x509.ts` reads, written here in the other
 * direction so the two are not one implementation checking itself.
 */
function oid(dotted: string): number[] {
  const arcs = dotted.split('.').map(Number);
  const out = [arcs[0] * 40 + arcs[1]];
  for (const arc of arcs.slice(2)) {
    const group: number[] = [arc & 0x7f];
    for (let v = arc >> 7; v > 0; v >>= 7) group.unshift((v & 0x7f) | 0x80);
    out.push(...group);
  }
  return der(0x06, out);
}

/** `SEQUENCE { AttributeType, AttributeValue }` inside a SET, as a Name is. */
const rdn = (type: string, value: string): number[] => set(seq(oid(type), utf8String(value)));

const AT_COUNTRY = '2.5.4.6';
const AT_ORG = '2.5.4.10';
const AT_CN = '2.5.4.3';

const SHA256_RSA = '1.2.840.113549.1.1.11';
const RSA_ENCRYPTION = '1.2.840.113549.1.1.1';

/** An extension: its id, its criticality when true, and its DER-in-an-OCTET STRING. */
function extension(id: string, critical: boolean, value: number[]): number[] {
  return critical ? seq(oid(id), bool(true), octetString(value)) : seq(oid(id), octetString(value));
}

/**
 * A 2048-bit RSA modulus that is not a product of two primes and does not need
 * to be: nothing here does arithmetic with it. What it has to be is the right
 * SIZE, because the key size is one of the facts under test and it is read as
 * the modulus's bit length.
 */
const MODULUS = Array.from({ length: 256 }, (_, i) => (i === 0 ? 0xc4 : (i * 37 + 11) & 0xff));

const NOT_BEFORE = '260101000000Z';
const NOT_AFTER = '270101000000Z';

const SUBJECT = seq(rdn(AT_COUNTRY, 'US'), rdn(AT_ORG, 'Example Corp'), rdn(AT_CN, 'www.example.com'));
const ISSUER = seq(rdn(AT_COUNTRY, 'US'), rdn(AT_ORG, 'Example Root CA'), rdn(AT_CN, 'Example Root R1'));

const TBS_CERTIFICATE = seq(
  explicit(0, integer([0x02])),                 // version: v3
  integer([0x10, 0x9e, 0x3f, 0x4a, 0x77]),      // serialNumber
  seq(oid(SHA256_RSA), nullTag()),              // signature
  ISSUER,
  seq(utcTime(NOT_BEFORE), utcTime(NOT_AFTER)), // validity
  SUBJECT,
  seq(                                          // subjectPublicKeyInfo
    seq(oid(RSA_ENCRYPTION), nullTag()),
    bitString(seq(integer(MODULUS), integer([0x01, 0x00, 0x01]))),
  ),
  explicit(3, seq(                              // extensions
    // basicConstraints: an end-entity certificate, said explicitly.
    extension('2.5.29.19', true, seq()),
    // keyUsage: digitalSignature + keyEncipherment. The bits are numbered from
    // the MSB of the first content byte, and the count of unused trailing bits
    // is what makes 0xa0 mean exactly those two.
    extension('2.5.29.15', true, bitString([0xa0], 5)),
    // extendedKeyUsage: serverAuth, clientAuth.
    extension('2.5.29.37', false, seq(oid('1.3.6.1.5.5.7.3.1'), oid('1.3.6.1.5.5.7.3.2'))),
    // subjectAltName, carrying one of each GeneralName form this build reads.
    extension('2.5.29.17', false, seq(
      implicit(2, [...'www.example.com'].map((c) => c.charCodeAt(0))),   // dNSName
      implicit(2, [...'*.example.com'].map((c) => c.charCodeAt(0))),     // dNSName, wildcard
      implicit(1, [...'hostmaster@example.com'].map((c) => c.charCodeAt(0))), // rfc822Name
      implicit(6, [...'https://example.com/'].map((c) => c.charCodeAt(0))),   // URI
      implicit(7, [192, 0, 2, 10]),                                      // iPAddress, v4
      implicit(7, [0x20, 0x01, 0x0d, 0xb8, ...Array(11).fill(0), 0x01]), // iPAddress, v6
    )),
    // authorityInfoAccess: OCSP responder and CA issuers.
    extension('1.3.6.1.5.5.7.1.1', false, seq(
      seq(oid('1.3.6.1.5.5.7.48.1'), implicit(6, [...'http://ocsp.example.com'].map((c) => c.charCodeAt(0)))),
      seq(oid('1.3.6.1.5.5.7.48.2'), implicit(6, [...'http://ca.example.com/r1.crt'].map((c) => c.charCodeAt(0)))),
    )),
    // cRLDistributionPoints: one DistributionPoint with a full name.
    extension('2.5.29.31', false, seq(
      seq(explicit(0, explicit(0, implicit(6, [...'http://crl.example.com/r1.crl'].map((c) => c.charCodeAt(0)))))),
    )),
  )),
);

const CERTIFICATE = seq(
  TBS_CERTIFICATE,
  seq(oid(SHA256_RSA), nullTag()),
  bitString(Array(256).fill(0x5a)),
);

/**
 * The issuer's own certificate, which is what a real chain carries above the
 * leaf and the only way `x509ce.cA` gets a value to read.
 *
 * `basicConstraints` on the leaf is an empty SEQUENCE - cA DEFAULTs to FALSE
 * and DER omits a default - so the reference shows nothing there, correctly.
 * A CA says `cA TRUE` outright, and a path length of 0 beside it, which is the
 * pair that says "may sign end-entity certificates and nothing below them".
 */
const CA_CERTIFICATE = seq(
  seq(
    explicit(0, integer([0x02])),
    integer([0x01]),
    seq(oid(SHA256_RSA), nullTag()),
    ISSUER,                                       // self-issued
    seq(utcTime(NOT_BEFORE), utcTime(NOT_AFTER)),
    ISSUER,
    seq(
      seq(oid(RSA_ENCRYPTION), nullTag()),
      bitString(seq(integer(MODULUS), integer([0x01, 0x00, 0x01]))),
    ),
    explicit(3, seq(
      extension('2.5.29.19', true, seq(bool(true), integer([0x00]))),
      extension('2.5.29.15', true, bitString([0x06], 1)),   // keyCertSign + cRLSign
    )),
  ),
  seq(oid(SHA256_RSA), nullTag()),
  bitString(Array(256).fill(0x5a)),
);

// --- the handshake ------------------------------------------------------------

const CLIENT = '192.0.2.10';
const SERVER = '198.51.100.20';
const CLIENT_PORT = 52000;

function ip(payload: Uint8Array, src: string, dst: string): Uint8Array {
  const header = new Bytes()
    .u8(0x45, 0x00).u16(20 + payload.length).u16(0x0001).u16(0x4000)
    .u8(64, 6).u16(0).ipv4(src).ipv4(dst).build();
  const sum = internetChecksum(header);
  header[10] = (sum >> 8) & 0xff;
  header[11] = sum & 0xff;
  return Uint8Array.from([...header, ...payload]);
}

function segment(fromClient: boolean, seqNum: number, ack: number, flags: number, body: number[]): Uint8Array {
  const tcp = Uint8Array.from([
    ...new Bytes()
      .u16(fromClient ? CLIENT_PORT : 443, fromClient ? 443 : CLIENT_PORT)
      .u32(seqNum).u32(ack).u8(0x50, flags).u16(64240, 0, 0).build(),
    ...body,
  ]);
  return Uint8Array.from([
    ...ethernet(0x0800).build(),
    ...(fromClient ? ip(tcp, CLIENT, SERVER) : ip(tcp, SERVER, CLIENT)),
  ]);
}

/** A TLS record: content type, version, length, body. */
const record = (type: number, body: number[]): number[] =>
  [type, 0x03, 0x03, (body.length >> 8) & 0xff, body.length & 0xff, ...body];

/** A handshake message: type, a three-byte length, body. */
const handshake = (type: number, body: number[]): number[] =>
  [type, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff, ...body];

const u24 = (n: number): number[] => [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];

/**
 * A minimal TLS 1.2 ClientHello. No extensions but server_name, because the
 * fingerprints are `scripts/tls/dissect.ts`'s subject and the certificate is
 * this one's.
 */
const SNI = 'www.example.com';
const CLIENT_HELLO = record(0x16, handshake(0x01, [
  0x03, 0x03,
  ...Array(32).fill(0x11),          // random
  0x00,                             // no session id
  0x00, 0x04, 0xc0, 0x2f, 0x00, 0x35, // two cipher suites
  0x01, 0x00,                       // one compression method: null
  // extensions: server_name only
  0x00, SNI.length + 9,
  0x00, 0x00, 0x00, SNI.length + 5,
  0x00, SNI.length + 3, 0x00, 0x00, SNI.length,
  ...[...SNI].map((c) => c.charCodeAt(0)),
]));

const SERVER_HELLO = record(0x16, handshake(0x02, [
  0x03, 0x03,
  ...Array(32).fill(0x22),
  0x00,
  0xc0, 0x2f,                       // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  0x00,                             // no compression
  0x00, 0x00,                       // no extensions
]));

const CERTIFICATE_MESSAGE = record(0x16, handshake(0x0b, [
  ...u24(CERTIFICATE.length + CA_CERTIFICATE.length + 6),
  ...u24(CERTIFICATE.length), ...CERTIFICATE,
  ...u24(CA_CERTIFICATE.length), ...CA_CERTIFICATE,
]));

const SERVER_HELLO_DONE = record(0x16, handshake(0x0e, []));

const SYN = 0x02, SYN_ACK = 0x12, ACK = 0x10, PSH_ACK = 0x18;

const FRAMES: { name: string; bytes: Uint8Array }[] = [
  { name: 'syn', bytes: segment(true, 1000, 0, SYN, []) },
  { name: 'syn-ack', bytes: segment(false, 2000, 1001, SYN_ACK, []) },
  { name: 'ack', bytes: segment(true, 1001, 2001, ACK, []) },
  { name: 'client hello', bytes: segment(true, 1001, 2001, PSH_ACK, CLIENT_HELLO) },
  {
    name: 'server hello',
    bytes: segment(false, 2001, 1001 + CLIENT_HELLO.length, PSH_ACK,
      [...SERVER_HELLO, ...CERTIFICATE_MESSAGE, ...SERVER_HELLO_DONE]),
  },
];

const directory = mkdtempSync(join(tmpdir(), 'inwire-tls-'));
const capture = join(directory, 'tls12.pcap');
writeFileSync(capture, pcapOf(FRAMES.map((f) => f.bytes)));

const { packets } = await PcapService.parseCaptureFile(
  new File([readFileSync(capture)], 'tls12.pcap'), Number.POSITIVE_INFINITY, true);

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

console.log('\n--- the leaf, read from the DER this file wrote ---');
const hello = at('server hello');
{
  check('the Protocol column names the version the handshake negotiated',
    hello.protocolLabel, 'TLSv1.2');
  check('both certificates in the chain are read',
    rows(hello).filter((r) => r.name.startsWith('Certificate')).length, 2);

  check('the version, which was never read at all', valueOf(hello, 'x509af.version'), 2);
  check('the serial number', valueOf(hello, 'x509af.serialNumber'), '10:9e:3f:4a:77');
  // `i++; // signature algorithm` is what this used to be.
  check('the algorithm the certificate was SIGNED with',
    valueOf(hello, 'x509af.algorithm.id'), 'sha256WithRSAEncryption');
  // The abbrev sits on the row showing the WHOLE name, because that is the row
  // a reader wants; the CN alone is what goes in the field bag, which is what
  // a filter reads.
  check('the composed subject and issuer', [
    valueOf(hello, 'tls.x509.subject_cn'), valueOf(hello, 'tls.x509.issuer_cn'),
  ], ['C=US, O=Example Corp, CN=www.example.com', 'C=US, O=Example Root CA, CN=Example Root R1']);
  check('...and the filter reads the leaf CNs alone', [
    fieldValue(hello, 'tls.x509.subject_cn'), fieldValue(hello, 'tls.x509.issuer_cn'),
  ], ['www.example.com', 'Example Root R1']);

  // **subjectAltName was filtered to dNSName**, so a certificate naming an
  // address, a mailbox or a URI read as one with fewer names or none at all.
  check('every dNSName, one row each',
    allValuesOf(hello, 'x509ce.dNSName'), ['www.example.com', '*.example.com']);
  check('the rfc822Name', allValuesOf(hello, 'x509ce.rfc822Name'), ['hostmaster@example.com']);
  check('the iPAddress SANs, told apart by length',
    [allValuesOf(hello, 'x509ce.IPAddress.ipv4'), allValuesOf(hello, 'x509ce.IPAddress.ipv6')],
    [['192.0.2.10'], ['2001:db8:0:0:0:0:0:1']]);
  // The SAN's URI, both access locations and the CRL distribution point, which
  // is one name for all four in the reference too.
  check('every URI in the certificate', allValuesOf(hello, 'x509ce.uniformResourceIdentifier'), [
    'https://example.com/',
    'http://ocsp.example.com',
    'http://ca.example.com/r1.crt',
    'http://crl.example.com/r1.crl',
  ]);

  check('basicConstraints says end-entity rather than saying nothing',
    allValuesOf(hello, 'x509ce.cA'), [false, true]);
  check('...and the CA above it carries a path length',
    valueOf(hello, 'x509ce.pathLenConstraint'), 0);
  // Bit 0 is the MOST significant bit of the first content byte, which is the
  // one thing about a DER BIT STRING that catches everybody.
  check('keyUsage, as the raw byte and as names',
    allValuesOf(hello, 'x509ce.KeyUsage'),
    ['a0 (digitalSignature, keyEncipherment)', '06 (keyCertSign, cRLSign)']);
  check('extendedKeyUsage, named', allValuesOf(hello, 'x509ce.KeyPurposeId'), ['serverAuth', 'clientAuth']);
  check('the access methods', allValuesOf(hello, 'pkix1implicit.accessMethod'), ['OCSP', 'caIssuers']);

  check('every extension is listed, named and with its criticality',
    rows(hello).filter((r) => r.abbrev === 'x509af.extension.id').map((r) => r.value),
    ['basicConstraints (critical)', 'keyUsage (critical)', 'extKeyUsage', 'subjectAltName',
      'authorityInfoAccess', 'cRLDistributionPoints', 'basicConstraints (critical)',
      'keyUsage (critical)']);

  // The key SIZE needed the SPKI BIT STRING opened rather than its algorithm
  // read off the front, and a 2048-bit modulus encodes as 257 bytes - so
  // reporting 2056 would be wrong in the direction that flatters it.
  const algorithm = rows(hello).find((r) => r.name === 'Public Key Algorithm');
  check('the key algorithm and its size', algorithm?.value, 'rsaEncryption (2048 bits)');
}

console.log('\n--- the chain in the protocol hierarchy ---');
{
  // Without these the barewords `x509af` and `x509ce` would validate as
  // filters and match nothing, which is a filter that lies rather than fails.
  check('the certificate puts x509 in frameProtocols',
    (hello.frameProtocols ?? []).filter((t) => t.startsWith('x509') || t === 'pkix1implicit'),
    ['x509af', 'x509ce', 'pkix1implicit']);
  check('a frame with no certificate claims none',
    (at('client hello').frameProtocols ?? []).some((t) => t.startsWith('x509')), false);
}

// --- what the reference makes of it -------------------------------------------
//
// Run FIRST, because the whole point of this file is that the certificate is
// readable by something other than the code under test. If tshark cannot parse
// what `der()` built, every assertion below is checking one bug against itself.

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
  console.log('\nSKIP  tshark not found - the assertions below ran; the cross-check did not.');
} else {
  console.log(`\n--- the reference reads the certificate this file built (${tshark}) ---`);
  const columns = [
    'x509af.version', 'x509af.serialNumber', 'x509af.algorithm.id',
    'x509ce.dNSName', 'x509ce.rfc822Name', 'x509ce.uniformResourceIdentifier',
    'x509ce.IPAddress.ipv4', 'x509ce.IPAddress.ipv6',
    'x509ce.cA', 'x509ce.KeyUsage', 'x509ce.KeyPurposeId',
    'x509af.extnId', 'x509af.critical', 'x509sat.uTF8String', 'frame.protocols',
  ];
  const out = execFileSync(tshark, ['-r', capture, '-T', 'fields',
    ...columns.flatMap((c) => ['-e', c]), '-E', 'separator=|'], { encoding: 'utf8' });
  const reference = out.trimEnd().split('\n').map((line) => {
    const cells = line.replace(/\r$/, '').split('|');
    return Object.fromEntries(columns.map((c, i) => [c, cells[i] ?? ''])) as Record<string, string>;
  });
  const theirs = reference[FRAMES.findIndex((f) => f.name === 'server hello')];

  // `-e` repeats a field once per occurrence and the chain has two
  // certificates, so every per-certificate field comes back twice.
  check('the reference reads the same versions and serials',
    [theirs['x509af.version'], theirs['x509af.serialNumber']], ['2,2', '109e3f4a77,01']);
  // `-e` repeats a field once per occurrence, comma separated - the leaf's
  // signature, its key algorithm and the outer signature, in that order.
  check('the reference reads the same signature algorithm',
    theirs['x509af.algorithm.id'].split(',')[0], '1.2.840.113549.1.1.11');
  check('the reference reads the same dNSNames',
    theirs['x509ce.dNSName'], 'www.example.com,*.example.com');
  check('...the same mailbox', theirs['x509ce.rfc822Name'], 'hostmaster@example.com');
  check('...the same two addresses',
    [theirs['x509ce.IPAddress.ipv4'], theirs['x509ce.IPAddress.ipv6']],
    ['192.0.2.10', '2001:db8::1']);
  check('...and files every URI under one name, as this build now does',
    theirs['x509ce.uniformResourceIdentifier'],
    'https://example.com/,http://ocsp.example.com,http://ca.example.com/r1.crt,http://crl.example.com/r1.crl');
  check('the reference reads the same key usage bits',
    theirs['x509ce.KeyUsage'], 'a0,06');
  check('...the same extended key usages',
    theirs['x509ce.KeyPurposeId'], '1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2');
  check('...and the same CA flag on the issuer', theirs['x509ce.cA'], 'True');
  // The composed Subject and Issuer this build publishes are assembled out of
  // exactly these, in this order: the CA's two attributes then the leaf's
  // three, leaf first in the message and issuer-name-first within each.
  check('the reference has the same names, through its own attribute tree',
    theirs['x509sat.uTF8String'],
    // The CA's name appears three times because it is the leaf's issuer and
    // then both halves of a self-issued certificate.
    'Example Root CA,Example Root R1,Example Corp,www.example.com,'
    + 'Example Root CA,Example Root R1,Example Root CA,Example Root R1');
  check('the reference puts x509 in its protocol chain too',
    theirs['frame.protocols'].includes(':x509ce:'), true);
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All TLS certificate checks passed.');
process.exit(0);
