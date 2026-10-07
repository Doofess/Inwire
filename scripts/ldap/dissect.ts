/**
 * LDAP, held to tshark on frames built from RFC 4511's own grammar.
 *
 *   npx tsx scripts/ldap/dissect.ts
 *
 * Neither fixture contains LDAP - they are desktop captures, and LDAP is a
 * thing corporate networks do - so `parity-check.ts` can say nothing about this
 * dissector. `scripts/parity/synthetic.ts` is the oracle instead: frames built
 * byte by byte here, written to a real `.pcap`, and read by the same tshark the
 * fixture harness uses.
 *
 * **Everything in the Info format below came from asking tshark, not from
 * reading RFC 4511**, and none of it is derivable from the standard:
 *
 * - Every message ends in a **trailing space**. `askTshark` strips the line
 *   ending and never trailing whitespace, so this is compared for real. It is
 *   the fifth dissector here to turn on trailing space after SIP's `" | "`,
 *   CDP's two, HTTP/1.1's one and LLDP's.
 * - Several messages in one segment join with `" | "` - and since each already
 *   ends in a space, the rendered result carries *two* before the bar.
 * - `searchResDone` reports `[N result]` / `[N results]`, singular only at one,
 *   after **two** spaces, and N counts the `searchResEntry` messages seen for
 *   that messageID earlier on the same connection. That is cross-frame state,
 *   which is the whole reason this protocol was worth doing: it is the first
 *   one here that is not a leaf.
 * - `abandonRequest` prints the messageID **it carries in its body** - the
 *   request being abandoned - not its own. A frame whose LDAPMessage id is 4
 *   and whose body is INTEGER 2 renders `abandonRequest(2)`.
 * - `extendedReq` names well-known OIDs: 1.3.6.1.4.1.1466.20037 is
 *   `LDAP_START_TLS_OID`.
 */
import { Bytes, tcpFrame, runCases, failureCount, type SyntheticCase } from '../parity/synthetic';
import { compareWithReference, finish } from '../parity/treeOracle';

// --- BER, written out rather than helper-ised --------------------------------
//
// The same discipline the rest of the synthetic suite follows: a test frame
// should read as the standard's own layout, so that it cannot be wrong in the
// same way the dissector is wrong. `ber.ts` is the code under test here, via
// the dissector - it must not also build the input.

function len(n: number): number[] {
  if (n < 0x80) return [n];
  if (n < 0x100) return [0x81, n];
  return [0x82, (n >> 8) & 0xff, n & 0xff];
}
function tlv(tag: number, body: number[]): number[] { return [tag, ...len(body.length), ...body]; }
function int(n: number): number[] { return tlv(0x02, [n]); }
function octets(s: string): number[] { return tlv(0x04, [...new Bytes().ascii(s).build()]); }
function ctx(tag: number, s: string): number[] { return tlv(tag, [...new Bytes().ascii(s).build()]); }
function enumerated(n: number): number[] { return tlv(0x0a, [n]); }

/** LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE, ... } */
function message(id: number, op: number[]): Uint8Array {
  return Uint8Array.from(tlv(0x30, [...int(id), ...op]));
}

const DN = 'cn=admin,dc=example,dc=com';
const BASE = 'dc=example,dc=com';

// The protocolOp tags are [APPLICATION n]: 0x60 | n when constructed,
// 0x40 | n when primitive (unbind, del, abandon).
const bindRequest = message(1, tlv(0x60, [...int(3), ...octets(DN), ...ctx(0x80, 'secret')]));
const bindResponse = message(1, tlv(0x61, [...enumerated(0), ...octets(''), ...octets('')]));
const bindFailure = message(1, tlv(0x61, [...enumerated(49), ...octets(''), ...octets('')]));
const searchRequest = message(2, tlv(0x63, [
  ...octets(BASE),
  ...enumerated(2),                 // scope: wholeSubtree
  ...enumerated(3),                 // derefAliases: derefAlways
  ...int(0), ...int(0),             // sizeLimit, timeLimit
  0x01, 0x01, 0x00,                 // typesOnly BOOLEAN false
  ...ctx(0x87, 'objectClass'),      // filter: [7] present
  ...tlv(0x30, []),                 // attributes: none
]));
const searchOneLevel = message(6, tlv(0x63, [
  ...octets(BASE), ...enumerated(1), ...enumerated(0), ...int(0), ...int(0),
  0x01, 0x01, 0x00, ...ctx(0x87, 'objectClass'), ...tlv(0x30, []),
]));
const searchResEntry = message(2, tlv(0x64, [
  ...octets(DN),
  ...tlv(0x30, tlv(0x30, [...octets('cn'), ...tlv(0x31, octets('admin'))])),
]));
const searchResDone = message(2, tlv(0x65, [...enumerated(0), ...octets(''), ...octets('')]));
const unbindRequest = message(3, tlv(0x42, []));
/** Its own messageID is 4; the one it names - and the one tshark prints - is 2. */
const abandonRequest = message(4, tlv(0x50, [0x02]));
const extendedReq = message(5, tlv(0x77, ctx(0x80, '1.3.6.1.4.1.1466.20037')));

/** A search whose filter exercises every shape: or, not, substrings, >=. */
const searchFilters = message(7, tlv(0x63, [
  ...octets(BASE), ...enumerated(2), ...enumerated(0), ...int(10), ...int(30), 0x01, 0x01, 0xff,
  ...tlv(0xa1, [                                            // or
    ...tlv(0xa3, [...octets('cn'), ...octets('alice')]),    //   (cn=alice)
    ...tlv(0xa4, [...octets('sn'), ...tlv(0x30, [...ctx(0x80, 'Smi'), ...ctx(0x81, 'th'), ...ctx(0x82, 's')])]), // (sn=Smi*th*s)
    ...tlv(0xa2, ctx(0x87, 'disabled')),                    //   (!(disabled=*))
    ...tlv(0xa5, [...octets('uidNumber'), ...octets('1000')]), // (uidNumber>=1000)
  ]),
  ...tlv(0x30, [...octets('cn'), ...octets('mail')]),
]));

/** Two LDAPMessages back to back in one segment. */
const entryThenDone = Uint8Array.from([...searchResEntry, ...searchResDone]);

// --- the conversation ---------------------------------------------------------
//
// One connection, in order, so the entry counter is exercised for real: the
// standalone Done reports 0, and the Done after two entries reports 2. Ports and
// sequence numbers are tracked by hand because a gap would make tshark print
// `[TCP Previous segment not captured]` and the comparison would fail on TCP
// analysis rather than on LDAP.

const CLIENT = 40000;
let cSeq = 1;
let sSeq = 1;
/** Client -> server on 389. */
const toServer = (payload: Uint8Array): Uint8Array => {
  const frame = tcpFrame(CLIENT, 389, cSeq, sSeq, payload);
  cSeq += payload.length;
  return frame;
};
/** Server -> client. */
const toClient = (payload: Uint8Array): Uint8Array => {
  const frame = tcpFrame(389, CLIENT, sSeq, cSeq, payload);
  sSeq += payload.length;
  return frame;
};

const cases: SyntheticCase[] = [
  { name: 'a simple bind names the DN and the mechanism', frame: toServer(bindRequest) },
  { name: '...and its response names the result code', frame: toClient(bindResponse) },
  { name: 'a search names the base object and the scope', frame: toServer(searchRequest) },
  // No entries yet for this messageID, so the count is zero - and plural at zero.
  { name: 'a searchResDone with no entries reports [0 results]', frame: toClient(searchResDone) },
  { name: 'a one-level search names its scope', frame: toServer(searchOneLevel) },
  { name: 'an entry names its object', frame: toClient(searchResEntry) },
  { name: 'a second entry on the same messageID', frame: toClient(searchResEntry) },
  // Two entries have gone past on messageID 2 since the last Done.
  { name: '...so the next searchResDone reports [2 results]', frame: toClient(searchResDone) },
  { name: 'a failed bind names its result code', frame: toClient(bindFailure) },
  { name: 'an abandon names the request it abandons, not itself', frame: toServer(abandonRequest) },
  { name: 'an extended request names a well-known OID', frame: toServer(extendedReq) },
  { name: 'unbind carries nothing but its id', frame: toServer(unbindRequest) },
  { name: 'two messages in one segment join with a bar', frame: toClient(entryThenDone) },
  { name: 'a search with or, substrings, not and >= in its filter', frame: toServer(searchFilters) },
];

// The same `main()` shape every other dissector suite here ends on, rather than
// a bare promise: `scripts/check.ts` discovers a script by looking for the
// literal `process.exit` in its source, so a suite that only exits through a
// helper is silently never run. `finish` still does the exiting.
async function main(): Promise<void> {
  await runCases(cases, { statefulTcp: true });
  const columnFailures = failureCount();
  // And the tree, row for row: asn2wrs's LDAPMessage structure, the filter as
  // a tree of its choices, matchedDN and errorMessage drawn when empty.
  await compareWithReference(cases.map((c) => ({ label: c.name, frame: c.frame })), { rows: /^ldap\./ });
  if (columnFailures > 0) process.exit(1);
  finish('LDAP');
}

main();
