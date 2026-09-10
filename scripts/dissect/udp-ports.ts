/**
 * No two UDP subdissectors claim the same port.
 *
 *   npx tsx scripts/dissect/udp-ports.ts
 *
 * `findUdpSubdissector` returns the **first** entry whose `claims` predicate
 * accepts, so if two entries overlapped the table's order would silently
 * become part of its meaning - and a protocol would be read by whichever
 * dissector happened to be listed first. Nothing in the type says that cannot
 * happen, so it is checked here rather than trusted to review.
 *
 * The table is also checked against the ports the rest of the parser claims
 * for itself. DNS, DHCP, QUIC and SSDP are dispatched before the table is
 * consulted, so an entry claiming 53 or 443 would be dead code that looks
 * live - the worst kind, because the dissector would be tested in isolation
 * and never reached in the app.
 */
import { UDP_SUBDISSECTORS, findUdpSubdissector } from '../../src/services/dissectors/udpDispatch';
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
  const matches = UDP_SUBDISSECTORS.filter((d) => d.claims(port, port, UNICAST)
    || d.claims(port, 50000, UNICAST) || d.claims(50000, port, UNICAST));
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
    findUdpSubdissector(port, 50000, UNICAST)?.token, token);
}

// --- HSRP, the one entry that reads the destination address -------------------------
//
// A datagram on 1985 to a host is not HSRP. That is the reference analyzer's
// rule, established by probing, and it lives in the table's predicate rather
// than in the dissector - so it is only testable from here.
console.log();
check('HSRP on its group is claimed',
  findUdpSubdissector(1985, 1985, '224.0.0.2')?.token, 'hsrp');
check('...and on the v2 group', findUdpSubdissector(1985, 1985, '224.0.0.102')?.token, 'hsrp');
check('...but not to a host', findUdpSubdissector(1985, 1985, UNICAST), null);
check('...nor to a different multicast group',
  findUdpSubdissector(1985, 1985, '224.0.0.9'), null);

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All UDP dispatch checks passed.');
process.exit(0);
