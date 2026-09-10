/**
 * BGP-4, held to tshark on frames built from RFC 4271.
 *
 *   npx tsx scripts/bgp/dissect.ts
 *
 * The fourth length-delimited message on a well-known TCP port, and the first
 * that has to READ THE STREAM rather than each segment. DNS-over-TCP, LDAP and
 * SMB2 all decline a message that runs past the captured bytes, which is
 * defensible when a split message is an oddity. A BGP session's dominant
 * traffic is the full-table UPDATE, which does not fit a segment - so half the
 * cases below are one message spread over three frames, and they are the point
 * of the suite rather than an edge case appended to it.
 *
 * `statefulTcp` is on for that reason: the carry lives on `TcpDirection.bgp`,
 * and decoding each case against a fresh tracker would throw away the very
 * thing under test.
 *
 * Everything asserted here was measured, and four answers are not what RFC
 * 4271 would suggest:
 *
 *  - Info is the message type and nothing else, however consequential the
 *    message. A NOTIFICATION tearing the session down reads as long as a
 *    KEEPALIVE.
 *  - Several messages in one segment join with `", "` - a fourth convention,
 *    after LDAP's `" | "`, SMB2's `"; "` and Kerberos reporting only the last.
 *  - An unknown type is `Unknown message type (0x09)`, lower-case hex and no
 *    trailing " Message".
 *  - The sixteen-byte marker is a hard gate: without it the frame is plain
 *    TCP, not a malformed BGP message. And it is still not enough on its own -
 *    the identical bytes on port 1790 are plain TCP, because the reference
 *    dispatches BGP on the port alone.
 */
import {
  tcpFrame, runCases, finish, failureCount, type SyntheticCase,
} from '../parity/synthetic';

const MARKER = new Array(16).fill(0xff);

/** One message: marker, a length covering the whole message, a type, a body. */
function message(type: number, body: number[] = [], marker = MARKER, lengthOverride?: number): number[] {
  const length = lengthOverride ?? 19 + body.length;
  return [...marker, (length >> 8) & 0xff, length & 0xff, type, ...body];
}

const keepalive = () => message(4);
const open = (as: number, hold: number, id: string, opts: number[] = []) => message(1, [
  4, (as >> 8) & 0xff, as & 0xff, (hold >> 8) & 0xff, hold & 0xff,
  ...id.split('.').map(Number), opts.length, ...opts,
]);
/** Withdraw 10.0.0.0/8, one ORIGIN attribute, announce 192.0.2.0/24. */
const update = () => message(2, [0, 2, 8, 10, 0, 4, 0x40, 1, 1, 0, 24, 192, 0, 2]);
const notification = (major: number, minor: number) => message(3, [major, minor]);
const routeRefresh = (afi: number, safi: number) => message(5, [(afi >> 8) & 0xff, afi & 0xff, 0, safi]);

/**
 * A full-table-sized UPDATE: 827 bytes, which is three segments at the 300
 * bytes this suite splits at. Not a contrived size - a real one carries
 * thousands of prefixes and runs to the 4 kB ceiling.
 */
const bigUpdate = (() => {
  const nlri: number[] = [];
  for (let i = 0; i < 200; i++) nlri.push(24, 198, 51, i & 0xff);
  return message(2, [0, 0, 0, 4, 0x40, 1, 1, 0, ...nlri]);
})();

/**
 * The two directions of one peering, each numbering its own bytes.
 *
 * A wrong sequence number shows up as `[TCP Previous segment not captured]` in
 * the reference's Info column and the comparison then fails on TCP analysis
 * rather than on BGP, which is the trap `tcpFrame`'s own comment names.
 */
let clientSeq = 1;
let serverSeq = 1;
const cases: SyntheticCase[] = [];
const fromClient = (name: string, bytes: number[], extra: Partial<SyntheticCase> = {}) => {
  const payload = Uint8Array.from(bytes);
  cases.push({ name, frame: tcpFrame(50001, 179, clientSeq, serverSeq, payload), ...extra });
  clientSeq += payload.length;
};
const fromServer = (name: string, bytes: number[], extra: Partial<SyntheticCase> = {}) => {
  const payload = Uint8Array.from(bytes);
  cases.push({ name, frame: tcpFrame(179, 50001, serverSeq, clientSeq, payload), ...extra });
  serverSeq += payload.length;
};

// --- the five message types --------------------------------------------------

fromClient('an OPEN reports its type and nothing about the AS', open(64512, 180, '192.0.2.1'));
fromServer('the peer OPEN reads the same way', open(64513, 180, '192.0.2.2'));
fromClient('a KEEPALIVE', keepalive());
fromServer('the peer KEEPALIVE', keepalive());
fromClient('an UPDATE says nothing about its prefixes', update());
// An UPDATE with both lengths zero is an End-of-RIB marker and the reference
// does not distinguish it - worth pinning, because a dissector that read the
// body would be tempted to.
fromClient('an End-of-RIB UPDATE is just an UPDATE', message(2, [0, 0, 0, 0]));
fromServer('a NOTIFICATION does not name the error it carries', notification(6, 2));
fromClient('a ROUTE-REFRESH', routeRefresh(1, 1));
// A Cease/Administrative Shutdown and a header error share the subcode 2 and
// mean different things - the tree separates them, the Info column does not.
fromServer('a header error reads exactly like the Cease above', notification(1, 2));

// --- capabilities, which change the length and nothing else -------------------

fromClient('an OPEN carrying a capability', open(64512, 90, '192.0.2.1', [2, 6, 1, 4, 0, 1, 0, 1]));

// --- several messages in one segment -----------------------------------------

fromClient('two messages in one segment join with ", "', [...keepalive(), ...update()]);
fromClient('three of the same message are listed three times',
  [...keepalive(), ...keepalive(), ...keepalive()]);
fromServer('the order is the wire order, not a canonical one', [...update(), ...keepalive()]);

// --- unknown and refused forms ------------------------------------------------

fromClient('an unknown type prints its hex code and no " Message"', message(9, [1, 2, 3]));
fromClient('type 0 is unknown too, and pads to two hex digits', message(0));
// The marker is the gate. Without it the frame is plain TCP - NOT a malformed
// BGP message, which is what a dissector keyed on the port alone would say.
fromClient('sixteen bytes that are not ones are not BGP at all', message(4, [], new Array(16).fill(0)));

// --- one message across three segments ----------------------------------------

// The reason this dissector keeps state at all. The reference gives the FIRST
// segment an empty Info column and the middle one the plain TCP line - an
// asymmetry that comes from where its dissector clears the column before
// asking for more bytes. An empty Info column tells a reader nothing, so this
// build gives the plain TCP line for both, which is what the reference itself
// gives for the middle segment.
//
// The expected line is built from the running counters rather than typed out,
// and the two are the same number by construction: each direction's first
// segment has sequence 1, so the relative numbering the Info column shows is
// the raw numbering these counters hold. Inserting a case above therefore
// moves both together instead of stranding a literal.
fromClient('the first segment of a big UPDATE', bigUpdate.slice(0, 300), {
  expectInfo: `50001 → 179 [PSH, ACK] Seq=${clientSeq} Ack=${serverSeq} Win=8192 Len=300`,
});
fromClient('the middle segment carries no boundary', bigUpdate.slice(300, 600));
// The frame that COMPLETES the message is the one that names it, and the
// KEEPALIVE riding behind it in the same segment is reported after it.
fromClient('the segment that completes it names it, then reads on',
  [...bigUpdate.slice(600), ...keepalive()]);
fromClient('the stream is back in step afterwards', keepalive());

// A boundary landing INSIDE the nineteen header bytes - the case the `header`
// carry exists for. Without it the direction would never resynchronise.
const pair = [...keepalive(), ...update()];
fromServer('a segment ending mid-header', pair.slice(0, 19 + 8));
fromServer('the rest of that header, and the message it opened', pair.slice(19 + 8));
fromServer('and the stream is still in step', keepalive());

async function main(): Promise<void> {
  await runCases(cases, { statefulTcp: true });
  if (failureCount() > 0) process.exit(1);
  finish('BGP');
}

void main();
