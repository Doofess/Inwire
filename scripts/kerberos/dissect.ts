/**
 * Kerberos held to tshark on synthetic frames.
 *
 *   npx tsx scripts/kerberos/dissect.ts
 *
 * Neither fixture contains a single Kerberos frame - they are personal desktop
 * captures and there is no KDC on that network - so `parity-check.ts` can say
 * nothing at all here, and every expectation below comes from asking tshark
 * rather than from reading RFC 4120. That distinction earned its keep: the RFC
 * names error 25 `KDC_ERR_PREAUTH_REQUIRED` and the reference prints
 * `KRB5KDC_ERR_PREAUTH_REQUIRED`, so a suite written from the specification
 * would have passed against a dissector no Wireshark user could recognise.
 *
 * The messages are built out of DER by hand, the way the LDAP suite builds
 * LDAPMessages: `ber.ts` is the code under test here, through the dissector, so
 * it must not also build the input.
 */
import {
  Bytes, udpFrame, tcpFrame, runCases, finish, failureCount, type SyntheticCase,
} from '../parity/synthetic';

// --- DER, written out rather than helper-ised --------------------------------

function len(n: number): number[] {
  if (n < 0x80) return [n];
  if (n < 0x100) return [0x81, n];
  return [0x82, (n >> 8) & 0xff, n & 0xff];
}
function tlv(tag: number, body: number[]): number[] { return [tag, ...len(body.length), ...body]; }

/** A non-negative INTEGER, minimally encoded with the sign bit kept clear. */
function int(n: number): number[] {
  const bytes: number[] = [];
  let v = n;
  do { bytes.unshift(v & 0xff); v = Math.floor(v / 256); } while (v > 0);
  if ((bytes[0] & 0x80) !== 0) bytes.unshift(0);
  return tlv(0x02, bytes);
}
const ascii = (s: string): number[] => [...new Bytes().ascii(s).build()];
/** GeneralString, which is what a KerberosString and a Realm are. */
const gstr = (s: string): number[] => tlv(0x1b, ascii(s));
const gtime = (s: string): number[] => tlv(0x18, ascii(s));
const octets = (b: number[]): number[] => tlv(0x04, b);
const bits = (b: number[]): number[] => tlv(0x03, [0, ...b]);
const seq = (...parts: number[][]): number[] => tlv(0x30, parts.flat());
/** `[n]` context-specific constructed - every field in a Kerberos message. */
const ctx = (n: number, body: number[]): number[] => tlv(0xa0 | n, body);
/** `[APPLICATION n]` constructed - the message envelope. */
const app = (n: number, body: number[]): number[] => tlv(0x60 | n, body);

const REALM = 'EXAMPLE.COM';

/** PrincipalName ::= SEQUENCE { [0] name-type, [1] SEQUENCE OF KerberosString } */
const principal = (nameType: number, ...names: string[]): number[] =>
  seq(ctx(0, int(nameType)), ctx(1, tlv(0x30, names.flatMap(gstr))));

/** EncryptedData, whose ciphertext is opaque and never read. */
const encPart = (kvno?: number): number[] => seq(
  ctx(0, int(18)),
  ...(kvno === undefined ? [] : [ctx(1, int(kvno))]),
  ctx(2, octets([0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef])),
);

const ticket = (): number[] => app(1, seq(
  ctx(0, int(5)), ctx(1, gstr(REALM)),
  ctx(2, principal(2, 'krbtgt', REALM)), ctx(3, encPart(2)),
));

/**
 * KDC-REQ-BODY. `till` and `nonce` are mandatory, so a body without them is
 * not one tshark will read - which is how the first draft of this suite
 * produced an empty Info column and looked like a dissector bug.
 */
const reqBody = (cname: string[] | null, sname: string[] | null): number[] => seq(
  ctx(0, bits([0x40, 0x81, 0x00, 0x10])),                  // kdc-options
  ...(cname ? [ctx(1, principal(1, ...cname))] : []),      // NT-PRINCIPAL
  ctx(2, gstr(REALM)),
  ...(sname ? [ctx(3, principal(2, ...sname))] : []),      // NT-SRV-INST
  ctx(5, gtime('20370913024805Z')),
  ctx(7, int(0x1f2e3d4c)),
  ctx(8, tlv(0x30, [...int(18), ...int(17), ...int(23)])),
);

/**
 * KDC-REQ numbers its fields from 1 - pvno is `[1]`, msg-type is `[2]` - where
 * every other message starts at 0. That offset is the whole reason
 * `msgTypeIndex` exists in the dissector, and these two frames are what hold it
 * honest: read `[1]` for the type here and an AS-REQ reports pvno 5 instead.
 */
const kdcReq = (msgType: number, body: number[]): number[] =>
  seq(ctx(1, int(5)), ctx(2, int(msgType)), ctx(4, body));

const kdcRep = (msgType: number): number[] => seq(
  ctx(0, int(5)), ctx(1, int(msgType)), ctx(3, gstr(REALM)),
  ctx(4, principal(1, 'user1')), ctx(5, ticket()), ctx(6, encPart()),
);

const krbError = (code: number): number[] => app(30, seq(
  ctx(0, int(5)), ctx(1, int(30)),
  ctx(4, gtime('20260908120000Z')), ctx(5, int(0)),
  ctx(6, int(code)),
  ctx(9, gstr(REALM)), ctx(10, principal(2, 'krbtgt', REALM)),
));

const asReq = Uint8Array.from(app(10, kdcReq(10, reqBody(['user1'], ['krbtgt', REALM]))));
const asRep = Uint8Array.from(app(11, kdcRep(11)));
const tgsReq = Uint8Array.from(app(12, kdcReq(12, reqBody(null, ['cifs', 'fileserver.example.com']))));
const tgsRep = Uint8Array.from(app(13, kdcRep(13)));
const apReq = Uint8Array.from(app(14, seq(
  ctx(0, int(5)), ctx(1, int(14)), ctx(2, bits([0x00, 0x00, 0x00, 0x20])),
  ctx(3, ticket()), ctx(4, encPart()),
)));
const apRep = Uint8Array.from(app(15, seq(ctx(0, int(5)), ctx(1, int(15)), ctx(2, encPart()))));
const krbSafe = Uint8Array.from(app(20, seq(
  ctx(0, int(5)), ctx(1, int(20)),
  ctx(2, seq(ctx(0, octets(ascii('hi'))), ctx(3, int(1)))),
  ctx(3, seq(ctx(0, int(1)), ctx(1, octets([0x01, 0x02])))),
)));
const krbPriv = Uint8Array.from(app(21, seq(ctx(0, int(5)), ctx(1, int(21)), ctx(3, encPart()))));

/**
 * The message-type field names the message, NOT the application tag.
 *
 * `[APPLICATION 10]` is the AS-REQ envelope and this one carries `msg-type 12`.
 * The reference prints TGS-REQ. Getting this backwards is the obvious mistake -
 * the tag is the outer, more visible discriminator - and nothing else in the
 * suite would catch it, because in every real message the two agree.
 */
const taggedAsReqTypedTgs = Uint8Array.from(app(10, kdcReq(12, reqBody(['user1'], null))));

// --- UDP: one message per datagram, no length prefix --------------------------

let port = 40000;
const toKdc = (payload: Uint8Array): Uint8Array => udpFrame(port++, 88, payload);
const fromKdc = (payload: Uint8Array): Uint8Array => udpFrame(88, port++, payload);

// --- TCP: a four-byte big-endian length in front of every message -------------

const framed = (payload: Uint8Array): Uint8Array => Uint8Array.from([
  (payload.length >>> 24) & 0xff, (payload.length >>> 16) & 0xff,
  (payload.length >>> 8) & 0xff, payload.length & 0xff,
  ...payload,
]);

const CLIENT = 50000;
let cSeq = 1;
let sSeq = 1;
const tcpToServer = (payload: Uint8Array): Uint8Array => {
  const frame = tcpFrame(CLIENT, 88, cSeq, sSeq, payload);
  cSeq += payload.length;
  return frame;
};

const cases: SyntheticCase[] = [
  // Info is the message NAME and nothing else - no principal, no realm. LDAP
  // prints the DN and SMB2 prints the filename, so this was the surprise.
  { name: 'an AS-REQ over UDP names itself and nothing else', frame: toKdc(asReq) },
  { name: 'an AS-REP', frame: fromKdc(asRep) },
  { name: 'a TGS-REQ', frame: toKdc(tgsReq) },
  { name: 'a TGS-REP', frame: fromKdc(tgsRep) },
  { name: 'an AP-REQ', frame: toKdc(apReq) },
  { name: 'an AP-REP', frame: fromKdc(apRep) },
  { name: 'a KRB-SAFE', frame: toKdc(krbSafe) },
  { name: 'a KRB-PRIV', frame: toKdc(krbPriv) },
  // The commonest error on a real domain: the KDC asking for pre-authentication.
  { name: 'an error names MITs spelling, not the RFCs', frame: fromKdc(Uint8Array.from(krbError(25))) },
  { name: '...and one with no KRB5 prefix at all', frame: fromKdc(Uint8Array.from(krbError(68))) },
  // Error code 0 is "no error", and the reference declines to name one that did
  // not happen: it prints the bare message name instead of the KRB Error form.
  { name: 'error code 0 prints the message name, not an error', frame: fromKdc(Uint8Array.from(krbError(0))) },
  // 30 is a hole in tshark's own table, between SVC_UNAVAILABLE and BAD_INTEGRITY.
  { name: 'an unnamed code prints lower-case hex', frame: fromKdc(Uint8Array.from(krbError(30))) },
  { name: 'the msg-type field names the message, not the application tag',
    frame: toKdc(taggedAsReqTypedTgs) },

  // TCP, one connection in order. A gap would make tshark print
  // `[TCP Previous segment not captured]` and fail the comparison on TCP
  // analysis rather than on Kerberos.
  { name: 'an AS-REQ over TCP, behind its length prefix', frame: tcpToServer(framed(asReq)) },
  // Not a join. LDAP joins several messages with " | " and SMB2 with "; ";
  // Kerberos shows the LAST one and no separator. Verified three ways against
  // tshark - AS,TGS reads TGS-REQ, TGS,AS reads AS-REQ, AS,TGS,AS reads AS-REQ.
  { name: 'two messages in one segment show the last, not a join',
    frame: tcpToServer(Uint8Array.from([...framed(asReq), ...framed(tgsReq)])) },
  { name: '...and three, so it is the last rather than the second',
    frame: tcpToServer(Uint8Array.from([...framed(tgsReq), ...framed(asReq), ...framed(tgsReq)])) },
  // Declined, not half-read: the length promises more than the segment carries,
  // so the message was never fully seen.
  //
  // **A stated divergence, and the only one in this suite.** The reference
  // labels the segment KRB5 and writes an EMPTY Info column - it holds the
  // bytes for reassembly, knows the port, and has nothing to say yet. This
  // build declines and keeps the TCP summary. Two reasons, and the first is
  // the stronger: LDAP already made this exact choice for the same case, and
  // one of the two behaving differently on an incomplete length-prefixed
  // message would be the surprise. The second is that a blank Info tells a
  // reader nothing, where `50001 -> 88 [PSH, ACK] Seq=1 Len=142` at least says
  // a segment arrived and how big it was.
  //
  // The price is stated rather than waved past: a `kerberos` filter in this
  // build will not select this segment and in Wireshark it would. That is the
  // trade, and it applies only to segments carrying no complete message.
  //
  // On its own connection so the sequence numbers in the expectation stay at 1
  // - and it is measured, not assumed: a fresh stream with no handshake reads
  // as plain TCP in tshark too, so the reassembly context is what decides.
  { name: 'an incomplete message is declined, where the reference blanks Info',
    frame: tcpFrame(CLIENT + 1, 88, 1, 1, Uint8Array.from([
      ((asReq.length + 500) >>> 24) & 0xff, ((asReq.length + 500) >>> 16) & 0xff,
      ((asReq.length + 500) >>> 8) & 0xff, (asReq.length + 500) & 0xff,
      ...asReq,
    ])),
    expectProtocol: 'TCP',
    expectInfo: '50001 → 88 [PSH, ACK] Seq=1 Ack=1 Win=8192 Len=142' },
];

async function main(): Promise<void> {
  await runCases(cases, { statefulTcp: true });
  if (failureCount() > 0) process.exit(1);
  finish('Kerberos');
}

void main();
