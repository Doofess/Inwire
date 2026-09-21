/**
 * Assertion tests for classifyIP.
 *
 *   npx tsx scripts/geoip/classify.ts
 *
 * This is the guard on the map's biggest source of nonsense. The classifier it
 * replaces tested five prefixes and let everything else through to the
 * geolocation API, so every mDNS and SSDP packet on the LAN - and every
 * link-local, CGNAT and TEST-NET address - was looked up as though it were a
 * routable host and pinned somewhere on the map.
 *
 * Only `public` is ever sent to a provider, so every row below that is NOT
 * `public` is a pin that no longer appears.
 */
import {
  classifyIP,
  isLocatable,
  resetGeoCacheForTests,
  type IpClass,
} from '../../src/services/geoIpService';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = actual === expected;
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${expected}`);
    console.log(`        actual   ${actual}`);
  }
}

/** [address, expected class, why it is in the table] */
const CASES: [string, IpClass, string][] = [
  // --- genuinely routable: the only class that gets looked up ---
  ['8.8.8.8', 'public', 'Google DNS'],
  ['1.1.1.1', 'public', 'Cloudflare DNS'],
  ['81.31.203.153', 'public', 'ordinary IPv4 host'],
  // A real, well-known public address rather than a made-up one: the
  // documentation range 2001:db8::/32 is classified `reserved` a few lines
  // down in geoIpService, so it cannot stand in for an ordinary host here.
  ['2606:4700:4700::1111', 'public', 'ordinary IPv6 host'],
  ['172.15.0.1', 'public', 'just below the private 172.16-31 block'],
  ['172.32.0.1', 'public', 'just above the private 172.16-31 block'],
  ['100.63.255.255', 'public', 'just below CGNAT'],
  ['100.128.0.0', 'public', 'just above CGNAT'],
  ['223.255.255.255', 'public', 'last address before multicast begins'],
  ['11.0.0.1', 'public', 'adjacent to 10/8 but routable'],

  // --- RFC1918 ---
  ['10.0.0.4', 'private', '10/8'],
  ['192.168.1.1', 'private', '192.168/16'],
  ['172.16.0.1', 'private', 'first of 172.16/12'],
  ['172.31.255.255', 'private', 'last of 172.16/12'],
  ['fd00::1', 'private', 'IPv6 ULA - the half that is actually used'],
  ['fc00::1', 'private', 'IPv6 ULA - the reserved half'],

  // --- loopback / unspecified ---
  ['127.0.0.1', 'loopback', '127/8'],
  ['127.1.2.3', 'loopback', '127/8 is a whole /8, not one address'],
  ['::1', 'loopback', 'IPv6 loopback'],

  // --- link-local ---
  ['169.254.1.1', 'link-local', 'APIPA - missed by the old classifier'],
  ['fe80::1', 'link-local', 'IPv6 link-local'],
  ['febf::1', 'link-local', 'top of fe80::/10'],

  // --- carrier-grade NAT: looks routable and often resolves, to the wrong place ---
  ['100.64.0.1', 'cgnat', 'first of 100.64/10 - missed by the old classifier'],
  ['100.127.255.255', 'cgnat', 'last of 100.64/10'],

  // --- multicast: the loudest offender on any real LAN ---
  ['224.0.0.251', 'multicast', 'mDNS - on virtually every network'],
  ['239.255.255.250', 'multicast', 'SSDP - on virtually every network'],
  ['224.0.0.1', 'multicast', 'all-hosts group'],
  ['239.0.0.1', 'multicast', 'top of 224/4'],
  ['ff02::1', 'multicast', 'IPv6 all-nodes'],
  ['ff00::', 'multicast', 'base of ff00::/8'],

  // --- broadcast ---
  ['255.255.255.255', 'broadcast', 'limited broadcast as a dotted quad'],

  // --- reserved / documentation / benchmark ---
  ['0.0.0.0', 'reserved', 'unspecified'],
  ['::', 'reserved', 'IPv6 unspecified'],
  ['192.0.2.1', 'reserved', 'TEST-NET-1'],
  ['198.51.100.1', 'reserved', 'TEST-NET-2'],
  ['203.0.113.1', 'reserved', 'TEST-NET-3'],
  ['198.18.0.1', 'reserved', 'benchmark range'],
  ['192.88.99.1', 'reserved', '6to4 relay anycast'],
  ['240.0.0.1', 'reserved', 'former class E'],
  ['2001:db8::1', 'reserved', 'IPv6 documentation prefix'],

  // --- not addresses at all ---
  ['System', 'invalid', "the app's own sentinel"],
  ['Broadcast', 'invalid', "the app's own sentinel"],
  ['N/A', 'invalid', 'placeholder that must never reach a URL'],
  ['example.com', 'invalid', 'a hostname, not an address'],
  ['999.999.999.999', 'invalid', 'octets out of range'],
  ['10.0.0', 'invalid', 'too few octets'],
  ['10.0.0.1.5', 'invalid', 'too many octets'],
  ['', 'invalid', 'empty string'],
  ['   ', 'invalid', 'whitespace only'],
];

for (const [ip, expected, why] of CASES) {
  check(`${ip || '(empty)'} -> ${expected}  (${why})`, classifyIP(ip), expected);
}

// isLocatable is the single question every caller actually asks, so it must
// stay in lockstep with the table above rather than drifting into its own rule.
check('isLocatable is true for a routable address', isLocatable('8.8.8.8'), true);
check('isLocatable is false for mDNS', isLocatable('224.0.0.251'), false);
check('isLocatable is false for a LAN address', isLocatable('192.168.1.1'), false);
check('isLocatable is false for a hostname', isLocatable('example.com'), false);

const disagreements = CASES.filter(([ip, cls]) => isLocatable(ip) !== (cls === 'public'));
check('isLocatable agrees with classifyIP on every case', disagreements.length, 0);

// --- Memoization must be invisible -----------------------------------------

/**
 * classifyIP caches its answers, because the geo map's route aggregation asks
 * about both endpoints of every packet on every recompute - 100,000 calls at
 * the buffer cap, twice a second.
 *
 * A cache is only ever allowed to make that faster, never to make it different.
 * These assert the two ways a memo can go wrong: returning a stale answer, and
 * returning a DIFFERENT address's answer because the key was wrong.
 */

// Same input, twice: the second call is a cache hit and must agree.
const firstPass = CASES.map(([ip]) => classifyIP(ip));
const secondPass = CASES.map(([ip]) => classifyIP(ip));
check(
  'every address classifies the same on a cache hit as on a miss',
  JSON.stringify(secondPass),
  JSON.stringify(firstPass),
);

// Clearing the cache must not change any answer either - if it does, something
// stateful leaked into what is supposed to be a pure function of the string.
resetGeoCacheForTests();
const afterReset = CASES.map(([ip]) => classifyIP(ip));
check(
  'and the same again after the cache is cleared',
  JSON.stringify(afterReset),
  JSON.stringify(firstPass),
);

// Distinct addresses must not collide. Interleaved deliberately: a cache keyed
// on something coarser than the whole string (a prefix, a truncation) passes a
// sequential test and fails this one.
resetGeoCacheForTests();
const interleaved: [string, IpClass][] = [
  ['8.8.8.8', 'public'],
  ['8.8.8.9', 'public'],
  ['192.168.1.1', 'private'],
  ['8.8.8.8', 'public'],
  ['192.168.1.2', 'private'],
  ['224.0.0.251', 'multicast'],
  ['192.168.1.1', 'private'],
  ['8.8.8.9', 'public'],
];
const collisions = interleaved.filter(([ip, expected]) => classifyIP(ip) !== expected);
check('interleaved lookups do not collide in the cache', collisions.length, 0);

// A near-miss pair that differs only in the last character, which is the
// cheapest way to catch a key built from a prefix.
resetGeoCacheForTests();
check('10.0.0.1 is private', classifyIP('10.0.0.1'), 'private');
check('...and 11.0.0.1, asked second, is still public', classifyIP('11.0.0.1'), 'public');

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
