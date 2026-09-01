/**
 * Assertion tests for route aggregation.
 *
 *   npx tsx scripts/geo/routes.ts
 *
 * Two behaviours here are easy to get subtly wrong and impossible to spot on a
 * live map: **direction independence**, without which every conversation is
 * drawn twice, and **stable tie-breaking**, without which a route carrying
 * equal amounts of two protocols recolours on every recount as packets arrive.
 */
import { aggregateRoutes, dominantProtocol } from '../../src/components/analytics/geoRoutes';
import type { Packet } from '../../src/types/packet';

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
function checkTrue(name: string, condition: boolean) {
  check(name, condition, true);
}

const PLACES: Record<string, [number, number]> = {
  'a.1': [34.78, 32.08],   // Tel Aviv
  'a.2': [34.781, 32.081], // a second host in the same city
  'b.1': [-74.01, 40.71],  // New York
  'c.1': [139.69, 35.69],  // Tokyo
};
const locate = (ip: string) => PLACES[ip] ?? null;

let nextId = 1;
function pkt(source: string, destination: string, protocol: string): Packet {
  return { id: nextId++, source, destination, protocol } as unknown as Packet;
}

// --- Direction independence --------------------------------------------------
{
  const routes = aggregateRoutes([
    pkt('a.1', 'b.1', 'TCP'),
    pkt('b.1', 'a.1', 'TCP'),
  ], locate);
  check('a request and its reply are one route', routes.length, 1);
  check('both packets are counted on it', routes[0].total, 2);
}

// --- Hosts in one place collapse onto one line -------------------------------
{
  const routes = aggregateRoutes([
    pkt('a.1', 'b.1', 'TCP'),
    pkt('a.2', 'b.1', 'TCP'),
  ], locate);
  check('two hosts in the same city share one route', routes.length, 1);
  check('their traffic is summed', routes[0].total, 2);
}

// --- Same-place traffic draws nothing ----------------------------------------
{
  const routes = aggregateRoutes([pkt('a.1', 'a.2', 'TCP')], locate);
  check('a route with both ends in one place is dropped', routes.length, 0);
}

// --- Unlocatable endpoints ---------------------------------------------------
{
  const routes = aggregateRoutes([
    pkt('a.1', 'unknown', 'TCP'),
    pkt('unknown', 'other', 'TCP'),
  ], locate);
  check('a packet with an unlocatable end draws nothing', routes.length, 0);
}

// --- Dominant protocol -------------------------------------------------------
{
  const routes = aggregateRoutes([
    pkt('a.1', 'b.1', 'TCP'),
    pkt('a.1', 'b.1', 'QUIC'),
    pkt('a.1', 'b.1', 'QUIC'),
  ], locate);
  check('the busiest protocol wins', routes[0].dominantProtocol, 'QUIC');
  check('per-protocol counts are kept', routes[0].counts, { TCP: 1, QUIC: 2 });
}

check('a tie is broken deterministically, not by insertion order',
  dominantProtocol({ TCP: 5, QUIC: 5 }), dominantProtocol({ QUIC: 5, TCP: 5 }));
check('the tie-break prefers the more specific protocol',
  dominantProtocol({ TCP: 5, QUIC: 5 }), 'QUIC');
check('an unknown protocol loses a tie to a known one',
  dominantProtocol({ WEIRD: 3, TCP: 3 }), 'TCP');

// --- Ordering and bounds -----------------------------------------------------
{
  const packets = [
    pkt('a.1', 'b.1', 'TCP'),
    pkt('a.1', 'c.1', 'TCP'), pkt('a.1', 'c.1', 'TCP'), pkt('a.1', 'c.1', 'TCP'),
  ];
  const routes = aggregateRoutes(packets, locate);
  check('routes come back busiest first', routes.map((r) => r.total), [3, 1]);
}

{
  // Far more distinct routes than the cap, to prove the quietest are what drop.
  const packets: Packet[] = [];
  const many: Record<string, [number, number]> = { hub: [0.5, 0.5] };
  for (let i = 0; i < 200; i++) many[`p${i}`] = [10 + i * 0.5, 20];
  const locateMany = (ip: string) => many[ip] ?? null;
  for (let i = 0; i < 200; i++) {
    for (let n = 0; n <= i % 5; n++) packets.push(pkt('hub', `p${i}`, 'TCP'));
  }
  const routes = aggregateRoutes(packets, locateMany);
  checkTrue(`the route count is capped (${routes.length})`, routes.length <= 60);
  checkTrue('what survives is the busiest',
    routes[0].total >= routes[routes.length - 1].total);
}

// --- Endpoints are exact, not the rounded key --------------------------------

/**
 * The bug this pins shipped and was reported from the running app: routes
 * stored the ROUNDED coordinates as their endpoints, so every line was drawn up
 * to half a kilometre from the marker it was supposed to touch. At world zoom
 * that is a fraction of a pixel; zoomed in, each line visibly ends in open
 * space beside its own icon.
 *
 * Rounding still decides which packets share a route. It just no longer decides
 * where that route is drawn.
 */
{
  // Coordinates chosen so rounding moves them: .xx7 rounds up, .xx3 down.
  const exactA: [number, number] = [34.78177, 32.08537];
  const exactB: [number, number] = [-74.00603, 40.71283];
  const here = new Map<string, [number, number]>([
    ['10.0.0.1', exactA],
    ['10.0.0.2', exactB],
  ]);
  const routes = aggregateRoutes(
    [pkt('10.0.0.1', '10.0.0.2', 'TCP')],
    (ip) => here.get(ip) ?? null,
  );

  check('one route', routes.length, 1);
  const drawn = [routes[0].from, routes[0].to];
  // Direction-independent ordering puts the smaller longitude first, so New
  // York leads and Tel Aviv follows.
  check('endpoints are the exact coordinates, untouched by the key rounding',
    drawn, [exactB, exactA]);

  // And the rounding still does its job: a second host a few hundred metres
  // from the first joins the same line rather than drawing its own.
  const nearby = new Map<string, [number, number]>([
    ['10.0.0.1', exactA],
    ['10.0.0.2', exactB],
    ['10.0.0.3', [exactB[0] + 0.001, exactB[1] + 0.001]],
  ]);
  const grouped = aggregateRoutes(
    [pkt('10.0.0.1', '10.0.0.2', 'TCP'), pkt("10.0.0.1", "10.0.0.3", "TCP")],
    (ip) => nearby.get(ip) ?? null,
  );
  check('hosts inside one rounded cell still share a single route', grouped.length, 1);
  check('and that route keeps the endpoints of the packet that created it',
    [grouped[0].from, grouped[0].to], [exactB, exactA]);
  check('with both packets counted on it', grouped[0].total, 2);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
