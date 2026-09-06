/**
 * Assertion tests for the TLS dissector: reassembly across segments, the
 * negotiated version, hello parsing, and the JA3 / JA3S / JA4 fingerprints.
 *
 *   npx tsx scripts/tls/dissect.ts
 *
 * The two hellos are real ones from the `inwire` fixture (frames 209 and 212)
 * with the server name replaced by an equal-length example name, which leaves
 * every length, hash input and fingerprint unchanged - JA3 and JA4 never hash
 * the SNI value, only its presence. The expected fingerprints are what tshark
 * 4.6.8 reports for those frames (docs/decisions/0004 on why the fixture
 * itself is not in the repository). The certificate is a self-signed one made
 * with openssl for www.example.com; no TLS 1.2 handshake exists in either
 * fixture to lift one from, which is also why tshark cannot cross-check it.
 */
import { dissectTlsSegment, parseClientHello, parseServerHello } from '../../src/services/dissectors/tls';
import { summarizeCertificate } from '../../src/services/dissectors/x509';
import { freshTlsConversation, freshTlsCursor } from '../../src/services/tcpStreamTracker';

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

const fromHex = (parts: string[]) => {
  const h = parts.join('');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
};

/** Frame 209's TCP payload: one Handshake record carrying a ClientHello. */
const CLIENT_HELLO = fromHex([
  '160301030a0100030603035ace2871231da8a5592d3e2d8f3db71d4a0b0e78244f3bfb6395dec7667d63f1204bf87355',
  '19659a733c673f06e69c3d1c4872933f91ecf4ab41cf353be7e88e00002813021301c02cc02bc030c02fc024c023c028',
  'c027c00ac009c014c013009d009c003d003c0035002f0100029500000013001100000e686f73742d612e6578616d706c',
  '65000500050100000000002b00050403040303000d001a00180804080508060401050102010403050302030202060106',
  '0300230000000a00080006001d00170018000b000201000010000e000c02683208687474702f312e31003300d000ce00',
  '1d0020825c7ffd57a35f2dcae34b6733a67376599ea5b9c7fdcb6f18bd1e315b02cd1b0017004104a6c82a33023af54a',
  '66e35f140b986ac35b0847c0d3812cc23fba279a750f9616af8aac12216beec42f5e3b8ae0661c9a9bae7edb077f1724',
  '9ad03e0c2eb239860018006104e3f27683f872accb383a78df3ec593cb1dcf6dd7d09835e74cc78cd089984b55d1b30d',
  '09576ffa3ed4bfad3671b12ad9275613e78b748d7f68a8b617da85f3d00ce3b58df6e626c5617da59c63bf107ca3a247',
  '726c3a26dcc5b2087445b3107d0031000000170000ff01000100002d000201010029013b010601000004489ed020774a',
  'bb1471666ee4d97d9866ff3677d2797dec7402c24c85feff21292d1f4b18179d8090d6671dc3471475c14a417d0f20d9',
  '30f3e935079d59d88d8df5cf645b8a19680fcaa6fae8d00edb20a198ac1d90865ddfa21a0da7d3827500664498191869',
  'ee904eab085834dffe7db8e964edd9a2932bf97249eb05e58a81ed4d3d6418349f661ea4f60107c4dbeb283f5f76d13a',
  'd11b963f0565aeacee592f48eeb271617edb0337b2293e0f82d10671bae8fe093314d11a1d0c394b3e9b6c533c938b02',
  '8c9e2f0c58b65e7b3b7107e5dbcd98c9f4235dd3b6739faa93297c1329085340063dfcd7a601cd99e3b4c6c3369c0727',
  '7e884f6138cc3530f8093aab0031309d755a1b3e49cbac8f1c145ebf57b4f3293af0ee6b67fe8e673754db183443d360',
  'd45d10cb25d83137cf7a09125236fd',
]);

/** Frame 212's TCP payload: ServerHello (TLS 1.3 negotiated) + Change Cipher Spec + encrypted handshake. */
const SERVER_HELLO = fromHex([
  '16030300800200007c0303b9c1ee078e40d9c2af647dd18e84ebc87a3c4ff7edddff68e55e33a9af3152af204bf87355',
  '19659a733c673f06e69c3d1c4872933f91ecf4ab41cf353be7e88e001302000034002b0002030400330024001d0020cb',
  'b0c54beac07632b7bd0dd1de68d999c88dd87e0932eb16e5d283cdd01d5b24002900020000140303000101170303002e',
  '1bc7013bc1eb6ac61cefa08fcdc4106dd266e46c1601e3c63287ba03901a98d9db60d758a0be64124e48fe6c29781703',
  '030045f7b3d320d45efdb5b2af770414d02b63aae4f1dca891b82ec7764259b77da526c7717b33fec26100f4532260e2',
  'd53ee7b22df381f661b28376696fefffa43d2dd48cb039d5',
]);

/** openssl req -x509 ... -subj "/C=US/O=Example Corp/CN=www.example.com" -addext "subjectAltName=DNS:www.example.com,DNS:example.com" */
const CERT_DER = fromHex([
  '308201fa308201a0a003020102021426a4ae752711608612a9cc814c869b3908d85923300a06082a8648ce3d04030230',
  '3e310b300906035504061302555331153013060355040a0c0c4578616d706c6520436f72703118301606035504030c0f',
  '7777772e6578616d706c652e636f6d301e170d3236303930343031313734345a170d3237303930343031313734345a30',
  '3e310b300906035504061302555331153013060355040a0c0c4578616d706c6520436f72703118301606035504030c0f',
  '7777772e6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004da37b7337066',
  'b51b64243dfb8485a94f9db84f82e6069eabd2abcbf6a097035a35ced953e6f32511c24a1c17ab69dde31b9fbfb211bd',
  '5c9d64e8919f46556e40a37c307a301d0603551d0e04160414826e58c8d571d490ffc0af2a6c78163f37f416dd301f06',
  '03551d23041830168014826e58c8d571d490ffc0af2a6c78163f37f416dd300f0603551d130101ff040530030101ff30',
  '270603551d110420301e820f7777772e6578616d706c652e636f6d820b6578616d706c652e636f6d300a06082a8648ce',
  '3d040302034800304502205c699af5c8a6a9fa4141528a48a50a4113c1675159d726d47776b7f5ff8deadf022100db28',
  'e6d4dc1bf80e55c16274dd547b120bf39d4c425f91de1229fcd1387a7141',
]);

// --- hellos -------------------------------------------------------------------

{
  const body = CLIENT_HELLO.subarray(5); // past the record header
  const h = parseClientHello(body)!;
  check('ClientHello parses', !!h, true);
  check('SNI', h.sni, 'host-a.example');
  check('ALPN', h.alpn, ['h2', 'http/1.1']);
  check('offered versions include TLS 1.3 and 1.2', h.supportedVersions.filter((v) => (v & 0x0f0f) !== 0x0a0a), [0x0304, 0x0303]);
  check('20 cipher suites', h.ciphers.length, 20);
  check('JA3 full string', h.ja3Full, '771,4866-4865-49196-49195-49200-49199-49188-49187-49192-49191-49162-49161-49172-49171-157-156-61-60-53-47,0-5-43-13-35-10-11-16-51-49-23-65281-45-41,29-23-24,0');
  check('JA3 matches tshark', h.ja3, 'd7268fba5c8ebdc86121861931c04402');
  check('JA4 matches tshark', h.ja4, 't13d2014h2_2b729b4bf6f3_1ea369dc5faa');
  check('no ECH extension in this hello', h.echPresent, false);
}

{
  const s = parseServerHello(SERVER_HELLO.subarray(5))!;
  check('ServerHello parses', !!s, true);
  check('selected cipher TLS_AES_256_GCM_SHA384', s.cipher, 0x1302);
  check('negotiated version from supported_versions is TLS 1.3', s.selectedVersion, 0x0304);
  check('JA3S matches tshark', s.ja3s, '2253c82f03b621c5144709b393fde2c9');
}

// --- record layer, one frame at a time -------------------------------------------

function segment(bytes: Uint8Array, frameId: number, cursor: ReturnType<typeof freshTlsCursor>, conv: ReturnType<typeof freshTlsConversation>) {
  return dissectTlsSegment(bytes, 0, bytes.length, { frameId, cursor, conversation: conv, inOrder: true, segmentSeq: frameId * 100000, gap: false });
}

{
  // A whole handshake in one segment.
  const conv = freshTlsConversation();
  const c2s = freshTlsCursor();
  const s2c = freshTlsCursor();
  const ch = segment(CLIENT_HELLO, 1, c2s, conv);
  check('a complete ClientHello record is TLS', ch.kind, 'tls');
  if (ch.kind === 'tls') {
    check('...labelled by its handshake version, not the 0x0301 record header', ch.result.protocolLabel, 'TLSv1.2');
    check('...with the Wireshark Info line', ch.result.info, 'Client Hello (SNI=host-a.example)');
    check('...and the fingerprints as fields', [ch.result.fields['tls.handshake.ja3'], ch.result.fields['tls.handshake.ja4']],
      ['d7268fba5c8ebdc86121861931c04402', 't13d2014h2_2b729b4bf6f3_1ea369dc5faa']);
  }
  const sh = segment(SERVER_HELLO, 2, s2c, conv);
  check('the ServerHello frame is TLS', sh.kind, 'tls');
  if (sh.kind === 'tls') {
    check('...labelled TLSv1.3 once supported_versions says so', sh.result.protocolLabel, 'TLSv1.3');
    check('...listing every record in the segment', sh.result.info, 'Server Hello, Change Cipher Spec, Application Data, Application Data');
  }
  check('the conversation remembers the negotiated version', conv.negotiatedVersion, 0x0304);
  // Application data from the client after that is TLSv1.3 too.
  const appData = new Uint8Array([23, 3, 3, 0, 4, 1, 2, 3, 4]);
  const ad = segment(appData, 3, c2s, conv);
  check('later records inherit the negotiated version in the other direction', ad.kind === 'tls' && ad.result.protocolLabel, 'TLSv1.3');
}

{
  // A content type this build does not decode still has to END a record.
  //
  // The ceiling on a valid record header was 24 (Heartbeat) - every type this
  // build renders - and that is the wrong question to ask. The ceiling decides
  // what may **resynchronise** a stream, not what may be read. The reference
  // analyzer's `ssl_is_valid_content_type` runs to 26: 25 is `tls12_cid`
  // (RFC 9146), 26 the DTLS 1.3 ACK.
  //
  // Rejecting them meant such a record could not close the desynchronised
  // region it opened, so the direction stayed lost and every following segment
  // came back `Ignored Unknown Record`. Measured over the two fixtures, that
  // one comparison was **632 Protocol and 632 Info mismatches**: netview
  // Protocol 96.16 -> 99.49%, Info 94.93 -> 98.86%.
  for (const contentType of [25, 26]) {
    const conv = freshTlsConversation();
    conv.negotiatedVersion = 0x0303;
    const cursor = freshTlsCursor();
    // Establish the direction as TLS first, so the strict check is off and the
    // content type is the only thing under test.
    segment(new Uint8Array([23, 3, 3, 0, 2, 0xaa, 0xbb]), 1, cursor, conv);
    // Then a record of the undecoded type, split so it can only complete if the
    // header was accepted and its length believed.
    const record = new Uint8Array(5 + 40);
    record.set([contentType, 3, 3, 0, 40]);
    const first = segment(record.subarray(0, 20), 2, cursor, conv);
    check(`content type ${contentType} opens a record`, first.kind, 'continuation');
    const rest = segment(record.subarray(20), 3, cursor, conv);
    check(`...and completing it does not desynchronise the stream`, rest.kind, 'tls');
    // ...and says NOTHING in the Info column while doing it. Asked directly,
    // tshark reads such a record - "Content Type: Connection ID (25)", with its
    // version and length - and writes no element to the column, so a frame
    // holding one plus trailing bytes reads as a bare `Ignored Unknown Record`.
    // Naming it gave `Unknown (25), Ignored Unknown Record` on 3 fixture frames
    // and cascaded to 22 more on netview; giving it the ignored wording instead
    // would have printed that wording twice.
    check(`...and contributes no element to the Info column`,
      rest.kind === 'tls' && rest.result.info, '');
    // The stream is back at a boundary, so an ordinary record after it reads
    // normally rather than as an ignored one.
    const after = segment(new Uint8Array([23, 3, 3, 0, 3, 1, 2, 3]), 4, cursor, conv);
    check(`...leaving the next Application Data readable`,
      after.kind === 'tls' && !after.result.info.includes('Ignored'), true);
  }
  // 27 is not assigned and must still be refused, or this is not a ceiling.
  const conv = freshTlsConversation();
  conv.negotiatedVersion = 0x0303;
  const cursor = freshTlsCursor();
  segment(new Uint8Array([23, 3, 3, 0, 2, 0xaa, 0xbb]), 1, cursor, conv);
  const unassigned = segment(new Uint8Array([27, 3, 3, 0, 3, 1, 2, 3]), 2, cursor, conv);
  check('content type 27 is still not a record header',
    unassigned.kind === 'tls' && unassigned.result.info.includes('Ignored'), true);
}

{
  // The case the whole file exists for: a 4,118-byte Application Data record
  // over three 1,428-byte segments (2 -> 3 -> 4), then a second record.
  const conv = freshTlsConversation();
  conv.negotiatedVersion = 0x0303;
  const cursor = freshTlsCursor();
  const record = new Uint8Array(5 + 4118);
  record.set([23, 3, 3, 4118 >> 8, 4118 & 0xff]);
  const seg = (from: number, to: number) => record.subarray(from, Math.min(to, record.length));
  const r2 = segment(seg(0, 1428), 2, cursor, conv);
  const r3 = segment(seg(1428, 2856), 3, cursor, conv);
  const r4 = segment(seg(2856, 4123), 4, cursor, conv);
  check('the segment carrying the record header completes nothing', r2.kind, 'continuation');
  check('the middle segment completes nothing', r3.kind, 'continuation');
  check('the segment carrying the last byte is the TLS frame', r4.kind, 'tls');
  if (r4.kind === 'tls') {
    check('...with Application Data as its Info', r4.result.info, 'Application Data');
    check('...naming the earlier frames to be marked "[TCP PDU reassembled in 4]"', r4.result.reassembledFrom, [2, 3]);
    check('...and a reassembly note with the byte split', r4.result.records[0].contributions, [{ frame: 2, bytes: 1423 }, { frame: 3, bytes: 1428 }, { frame: 4, bytes: 1267 }]);
    check('...as a flag for filters', r4.result.fields['tls.reassembled'], 1);
  }
  check('the cursor is back at a record boundary', cursor.remaining, 0);

  // A frame that finishes one record and starts the next shows the finished
  // one and is not listed among the next record's segments.
  const tail = new Uint8Array(5 + 1000 + 5 + 400);
  tail.set([23, 3, 3, 1000 >> 8, 1000 & 0xff], 0);
  tail.set([23, 3, 3, 3000 >> 8, 3000 & 0xff], 1005);
  const f5 = segment(tail, 5, cursor, conv);
  check('a frame completing one record and starting another is TLS', f5.kind === 'tls' && f5.result.info, 'Application Data');
  check('...and the next record remembers no contributor yet', cursor.contributors, []);
  const rest = new Uint8Array(3000 - 400);
  const f6 = segment(rest, 6, cursor, conv);
  check('the frame that completes the next record lists only frames after it started', f6.kind === 'tls' && f6.result.reassembledFrom, []);
}

{
  // A record header split 3 + 2 across a segment boundary.
  const conv = freshTlsConversation();
  const cursor = freshTlsCursor();
  cursor.unknown = false;
  const head = new Uint8Array([23, 3, 3]);
  const rest = new Uint8Array([0, 2, 0xaa, 0xbb]);
  check('three header bytes alone are a continuation', segment(head, 7, cursor, conv).kind, 'continuation');
  const done = segment(rest, 8, cursor, conv);
  check('the header completes in the next frame and so does the record', done.kind === 'tls' && done.result.info, 'Application Data');
  check('...crediting the frame that carried the first header bytes', done.kind === 'tls' && done.result.reassembledFrom, [7]);
}

{
  // Not TLS at all: no cursor state should be claimed, no label given.
  const conv = freshTlsConversation();
  const cursor = freshTlsCursor();
  const http = new TextEncoder().encode('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
  check('an HTTP request is not TLS', segment(http, 9, cursor, conv).kind, 'none');
  check('...and the direction stays unknown', cursor.unknown, true);
}

{
  // Wireshark's resync rules on a direction already known to be TLS: a
  // header is any valid content-type byte, whatever the version or length
  // say; trailing bytes that begin no record are "Ignored Unknown Record".
  const conv = freshTlsConversation();
  conv.negotiatedVersion = 0x0303;
  const cursor = freshTlsCursor();
  cursor.unknown = false;
  const junkVersion = new Uint8Array([21, 0x69, 0x7a, 0, 4, 1, 2, 3, 4, 0xe9, 0x3e, 0x34]);
  const r = segment(junkVersion, 12, cursor, conv);
  check('a known direction accepts a header with a junk version', r.kind === 'tls' && r.result.info, 'Encrypted Alert, Ignored Unknown Record');
  check('...and the row keeps the conversation version', r.kind === 'tls' && r.result.protocolLabel, 'TLSv1.2');
  const fresh = freshTlsCursor();
  check('an unknown direction does not', segment(junkVersion, 13, fresh, freshTlsConversation()).kind, 'none');
}

{
  // A plaintext alert.
  const conv = freshTlsConversation();
  const alert = new Uint8Array([21, 3, 3, 0, 2, 1, 0]);
  const a = segment(alert, 10, freshTlsCursor(), conv);
  check('a plaintext close_notify is decoded', a.kind === 'tls' && a.result.info, 'Alert (Level: Warning, Description: Close Notify)');
  const enc = new Uint8Array([21, 3, 3, 0, 26, ...new Array(26).fill(0x5a)]);
  const e = segment(enc, 11, freshTlsCursor(), conv);
  check('an encrypted alert is named as such', e.kind === 'tls' && e.result.info, 'Encrypted Alert');
}

// --- certificate --------------------------------------------------------------------

{
  const c = summarizeCertificate(CERT_DER)!;
  check('certificate parses', !!c, true);
  check('subject CN', c.subjectCN, 'www.example.com');
  check('subject', c.subject, 'C=US, O=Example Corp, CN=www.example.com');
  check('SANs', c.dnsNames, ['www.example.com', 'example.com']);
  check('self-signed is detected', c.selfSigned, true);
  check('validity is a year', c.notAfter && c.notBefore ? (c.notAfter.getTime() - c.notBefore.getTime()) / 86_400_000 : null, 365);
  check('key type', c.keyType, 'id-ecPublicKey');
  check('garbage is not a certificate', summarizeCertificate(new Uint8Array([1, 2, 3])), null);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All TLS checks passed.');
process.exit(0);
