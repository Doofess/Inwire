/**
 * Assertion tests for the dissector table (`src/services/dissectors/dispatch.ts`).
 *
 *   npx tsx scripts/dissect/dispatch.ts
 *
 * This was `udp-ports.ts` and covered one of the four dispatch mechanisms this
 * build had. The table now holds three of them - ethertype, IP protocol number
 * and UDP port - so the checks that were about UDP's predicate list are about
 * the registry, and three more have been added that the old chains had only by
 * accident:
 *
 *   * **No two entries in a table claim the same value.** `findEntry` returns
 *     the first match, so an overlap would make declaration order meaningful -
 *     which is a property nobody would know to preserve.
 *   * **No entry claims a value dispatched before the table is consulted.**
 *     Such an entry is unreachable and looks like a working registration.
 *   * **Every token is a real `LAYERS` entry**, or the protocol gets an
 *     underscore-mangled bareword in `frameProtocols` and no filter finds it.
 *   * **`values: []` implies `claims`.** An entry claiming nothing and
 *     deciding nothing is unreachable in the other direction.
 *   * **Every entry survives a hostile buffer.** Each is called against
 *     zero-filled, all-`0xff` and truncated input and must return `null` or a
 *     well-formed `LeafResult` - never throw. That is both a type-rot check
 *     and the cheapest fuzz available, and it is the one the old file did not
 *     do: a leaf dissector that throws takes the whole frame down.
 */
import { findEntry, registeredEntries } from '../../src/services/dissectors/dispatch';
import { LAYERS } from '../../src/services/dissect/fieldRegistry';
import { VXLAN_PORTS } from '../../src/services/dissectors/vxlan';

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

/**
 * Ports the parser dispatches before it consults the table.
 *
 * Kept in step with `pcapParser.ts` by the assertion below rather than by
 * hand: an entry claiming one of these would never be reached.
 */
const CLAIMED_ELSEWHERE = [
  53, 5353, 5355,        // DNS, mDNS, LLMNR
  137,                   // NBNS
  67, 68, 546, 547,      // DHCP and DHCPv6
  443,                   // QUIC
  1900,                  // SSDP
  // Earlier still: VXLAN is read in `networkLayer.ts`, before the transport
  // decoder is called at all, because a tunnel decides the ADDRESS columns and
  // that is the function which owns them. Taken from the dissector's own
  // constant rather than written out, so the two cannot drift.
  ...VXLAN_PORTS,
];

// A destination that is not any protocol's multicast group, so an entry that
// gates on the address does not claim these by accident.
const UNICAST = '192.0.2.2';

console.log('Every port claimed by at most one subdissector:\n');

// The whole low port range plus the registered ports these protocols live in.
// Cheap enough to sweep exhaustively, which beats listing the ports by hand
// and then not noticing when an entry gains one.
const overlaps: string[] = [];
const claimedBy = new Map<number, string[]>();
for (let port = 1; port <= 65535; port++) {
  const matches = registeredEntries().filter((e) => e.table === 'udp.port'
    && e.values.includes(port)
    && (e.claims === undefined || e.claims({ srcPort: port, dstPort: port, dstAddress: UNICAST })));
  if (matches.length === 0) continue;
  const tokens = [...new Set(matches.map((m) => m.token))];
  claimedBy.set(port, tokens);
  if (matches.length > 1) overlaps.push(`${port}: ${matches.map((m) => m.token).join(', ')}`);
}
check('no port is claimed twice', overlaps, []);

// --- and none of them is a port the parser already handles ----------------------
const shadowed = CLAIMED_ELSEWHERE.filter((port) => claimedBy.has(port))
  .map((port) => `${port}: ${claimedBy.get(port)!.join(', ')}`);
check('no entry claims a port dispatched before the table', shadowed, []);

// --- the ports each protocol is supposed to answer on -----------------------------
//
// Stated rather than derived, so a predicate that quietly stops matching its
// own port fails here instead of going unnoticed until somebody captures one.
const EXPECTED: [number, string][] = [
  [5060, 'sip'], [5061, 'sip'],
  [161, 'snmp'], [162, 'snmp'],
  [514, 'syslog'],
  [1812, 'radius'], [1813, 'radius'], [1645, 'radius'], [1646, 'radius'],
  [69, 'tftp'],
  [138, 'nbdgm'],
  [3784, 'bfd'], [4784, 'bfd'], [3785, 'bfd'],
  [5683, 'coap'], [5684, 'coap'],
  [319, 'ptp'], [320, 'ptp'],
  [520, 'rip'], [521, 'ripng'],
];
console.log();
for (const [port, token] of EXPECTED) {
  check(`port ${port} is read by ${token}`,
    findEntry('udp.port', [port, 50000], { srcPort: port, dstPort: 50000, dstAddress: UNICAST })?.token, token);
}

// --- HSRP, the one entry that reads the destination address -------------------------
//
// A datagram on 1985 to a host is not HSRP. That is the reference analyzer's
// rule, established by probing, and it lives in the table's predicate rather
// than in the dissector - so it is only testable from here.
console.log();
check('HSRP on its group is claimed',
  findEntry('udp.port', [1985, 1985], { srcPort: 1985, dstPort: 1985, dstAddress: '224.0.0.2' })?.token, 'hsrp');
check('...and on the v2 group', findEntry('udp.port', [1985, 1985], { srcPort: 1985, dstPort: 1985, dstAddress: '224.0.0.102' })?.token, 'hsrp');
check('...but not to a host', findEntry('udp.port', [1985, 1985], { srcPort: 1985, dstPort: 1985, dstAddress: UNICAST }), null);
check('...nor to a different multicast group',
  findEntry('udp.port', [1985, 1985], { srcPort: 1985, dstPort: 1985, dstAddress: '224.0.0.9' }), null);

// --- every token is a layer the rest of the build knows -------------------------
//
// A token missing from `LAYERS` reaches `frameProtocols` as an
// underscore-mangled bareword, so the protocol is dissected, drawn, and
// invisible to every filter that names it.
console.log();
{
  const unknown = [...new Set(registeredEntries().map((e) => e.token))]
    .filter((token) => !(LAYERS as readonly string[]).includes(token)).sort();
  check('every registered token is a LAYERS entry', unknown, []);

  const undecidable = registeredEntries()
    .filter((e) => e.values.length === 0 && e.claims === undefined)
    .map((e) => e.token);
  check('no entry claims nothing and decides nothing', undecidable, []);

  const dupes: string[] = [];
  for (const table of ['ethertype', 'ip.proto', 'udp.port'] as const) {
    const seen = new Map<number, string>();
    for (const e of registeredEntries().filter((x) => x.table === table)) {
      for (const v of e.values) {
        const prior = seen.get(v);
        if (prior !== undefined) dupes.push(`${table} ${v}: ${prior}, ${e.token}`);
        else seen.set(v, e.token);
      }
    }
  }
  check('no two entries in a table claim the same value', dupes, []);
}

// --- and none of them throws on a buffer it was not expecting -------------------
//
// The check the predicate list never had, and the one with a whole frame
// behind it: a leaf dissector that throws is not a missing layer, it is an
// exception out of `decodeRawEthernetPacket` and a frame that never arrives.
// Three shapes, because they fail differently - zeroes are a plausible header
// with every length zero, 0xff is every length at its maximum, and a
// truncated buffer is the one a capture actually produces.
console.log();
{
  const shapes: [string, Uint8Array][] = [
    ['all zeroes', new Uint8Array(64)],
    ['all ones', new Uint8Array(64).fill(0xff)],
    ['truncated', new Uint8Array(3).fill(0xff)],
  ];
  const threw: string[] = [];
  const malformed: string[] = [];
  for (const entry of registeredEntries()) {
    for (const [what, bytes] of shapes) {
      let read;
      try {
        read = entry.dissect(bytes, 0, bytes.length);
      } catch (error) {
        threw.push(`${entry.token} on ${what}: ${error instanceof Error ? error.message : String(error)}`);
        continue;
      }
      if (read === null) continue;
      if (typeof read.protocolLabel !== 'string' || typeof read.info !== 'string'
        || read.layer === undefined || !Array.isArray(read.layer.fields)) {
        malformed.push(`${entry.token} on ${what}`);
      }
    }
  }
  check('no entry throws on a hostile buffer', threw, []);
  check('...and what it does return is a LeafResult', malformed, []);
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All dispatch table checks passed.');
process.exit(0);
