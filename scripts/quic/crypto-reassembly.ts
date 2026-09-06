/**
 * Assertion tests for QUIC CRYPTO reassembly - how a QUIC connection's server
 * name, ALPN and fingerprint are recovered.
 *
 *   npx tsx scripts/quic/crypto-reassembly.ts
 *
 * A QUIC ClientHello is inside an encrypted packet, split across CRYPTO frames
 * at arbitrary offsets, in arbitrary order, across more than one Initial
 * packet - one fixture has a hello arriving as ten fragments over two packets
 * with offsets counting down. It does not fit in a single packet at all once a
 * post-quantum key share is in it. So the fragments are filled into a sparse
 * buffer and parsed only when the stream is contiguous from zero and holds the
 * whole message its own header declares; parsing a hole as data yields a
 * fingerprint that matches nothing, which is worse than no fingerprint.
 *
 * The handshake bytes here are assembled from a synthetic ClientHello, so the
 * test carries no captured traffic.
 */
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';

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

// --- a synthetic ClientHello ----------------------------------------------------

function clientHello(sni: string, alpn: string[]): Uint8Array {
  const b: number[] = [];
  const u16 = (v: number) => b.push((v >> 8) & 0xff, v & 0xff);

  b.push(0x03, 0x03);                       // legacy_version TLS 1.2
  for (let i = 0; i < 32; i++) b.push(i);   // random
  b.push(0);                                // session id length
  u16(4); u16(0x1301); u16(0x1302);         // two cipher suites
  b.push(1, 0);                             // one compression method: null

  const ext: number[] = [];
  const extU16 = (v: number) => ext.push((v >> 8) & 0xff, v & 0xff);
  // server_name
  const nameBytes = [...sni].map((c) => c.charCodeAt(0));
  extU16(0); extU16(nameBytes.length + 5); extU16(nameBytes.length + 3);
  ext.push(0); extU16(nameBytes.length); ext.push(...nameBytes);
  // application_layer_protocol_negotiation
  const alpnBody: number[] = [];
  for (const a of alpn) { alpnBody.push(a.length); for (const c of a) alpnBody.push(c.charCodeAt(0)); }
  extU16(16); extU16(alpnBody.length + 2); extU16(alpnBody.length); ext.push(...alpnBody);
  // supported_versions: TLS 1.3
  extU16(43); extU16(3); ext.push(2); extU16(0x0304);
  // supported_groups: x25519
  extU16(10); extU16(4); extU16(2); extU16(29);

  u16(ext.length);
  b.push(...ext);

  const body = Uint8Array.from(b);
  const out = new Uint8Array(4 + body.length);
  out[0] = 1;                                        // Client Hello
  out[1] = (body.length >> 16) & 0xff;
  out[2] = (body.length >> 8) & 0xff;
  out[3] = body.length & 0xff;
  out.set(body, 4);
  return out;
}

const HELLO = clientHello('www.example.com', ['h3']);
const A = { ip: '192.0.2.10', port: 50000 };
const B = { ip: '198.51.100.5', port: 443 };
const add = (t: QuicFlowTracker, frags: { offset: number; data: Uint8Array }[]) =>
  t.addCryptoFragments(A.ip, A.port, B.ip, B.port, frags);

// --- one fragment, whole hello ----------------------------------------------------

{
  const t = new QuicFlowTracker();
  const facts = add(t, [{ offset: 0, data: HELLO }]);
  check('a hello in one fragment parses', facts?.hello?.sni, 'www.example.com');
  check('...with its ALPN', facts?.hello?.alpn, ['h3']);
  check('...and a JA4 marked as QUIC, not TCP', facts?.hello?.ja4.startsWith('q'), true);
  check('...naming TLS 1.3 from supported_versions', facts?.hello?.ja4.slice(1, 3), '13');
  check('the flow remembers the server name', t.sniFor(A.ip, A.port, B.ip, B.port), 'www.example.com');
  check('a second copy of the same fragment does not reparse', add(t, [{ offset: 0, data: HELLO }]), undefined);
}

// --- split, out of order, across two packets ---------------------------------------

{
  const t = new QuicFlowTracker();
  const cut1 = 40, cut2 = 90;
  const third = { offset: cut2, data: HELLO.subarray(cut2) };
  const first = { offset: 0, data: HELLO.subarray(0, cut1) };
  const second = { offset: cut1, data: HELLO.subarray(cut1, cut2) };

  // Arrives last-first, as the fixtures do.
  check('a trailing fragment alone completes nothing', add(t, [third]), undefined);
  check('...and so does the middle one', add(t, [second]), undefined);
  const facts = add(t, [first]);
  check('the fragment that closes the gap yields the hello', facts?.hello?.sni, 'www.example.com');
}

{
  const t = new QuicFlowTracker();
  // A hole in the middle must never be parsed as data.
  const facts = add(t, [
    { offset: 0, data: HELLO.subarray(0, 20) },
    { offset: 40, data: HELLO.subarray(40) },
  ]);
  check('a stream with a hole yields nothing', facts, undefined);
  const closed = add(t, [{ offset: 20, data: HELLO.subarray(20, 40) }]);
  check('...until the hole is filled', closed?.hello?.sni, 'www.example.com');
}

{
  const t = new QuicFlowTracker();
  // Only the header has arrived: the declared length says more is coming.
  check('a header with no body yields nothing', add(t, [{ offset: 0, data: HELLO.subarray(0, 4) }]), undefined);
  check('...and the rest completes it', add(t, [{ offset: 4, data: HELLO.subarray(4) }])?.hello?.sni, 'www.example.com');
}

// --- directions are separate streams -------------------------------------------------

{
  const t = new QuicFlowTracker();
  // The same offsets travelling the other way must not fill this direction's gaps.
  t.addCryptoFragments(B.ip, B.port, A.ip, A.port, [{ offset: 0, data: HELLO.subarray(0, 30) }]);
  check('the other direction does not complete this one',
    t.addCryptoFragments(A.ip, A.port, B.ip, B.port, [{ offset: 30, data: HELLO.subarray(30) }]), undefined);
}

// --- nothing to do ---------------------------------------------------------------------

{
  const t = new QuicFlowTracker();
  check('no fragments, no work', add(t, []), undefined);
  check('a fragment past the size ceiling is ignored', add(t, [{ offset: 1_000_000, data: HELLO }]), undefined);
  check('...and the flow has no name', t.sniFor(A.ip, A.port, B.ip, B.port), undefined);
  t.reset();
  check('reset clears the streams', add(t, [{ offset: 4, data: HELLO.subarray(4) }]), undefined);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All QUIC CRYPTO checks passed.');
process.exit(0);
