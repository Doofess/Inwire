import type { Packet } from '../../types/packet';
import type { LngLat } from '../../lib/greatCircle';

/**
 * Turning a packet buffer into the lines the map draws.
 *
 * What this replaces was a `slice(-20)` producing one line per packet, which
 * had three problems at once. Twenty packets is a fraction of a second on a
 * live link, so lines flickered in and out constantly; a busy route and a
 * single stray packet were drawn identically; and nothing said what was
 * flowing, because every line was the same colour regardless.
 *
 * Aggregating instead means a line represents a *relationship* rather than a
 * packet, which is what lets it carry a dominant protocol and a weight.
 */

export interface Route {
  /** Canonical, direction-independent identity for this pair of places. */
  key: string;
  from: LngLat;
  to: LngLat;
  /** Packets seen per protocol, which is what `dominantProtocol` argmaxes. */
  counts: Record<string, number>;
  total: number;
  dominantProtocol: string;
}

/**
 * Coordinate rounding for the route KEY, in decimal places.
 *
 * Two places is a little over a kilometre, which is the point: hosts in one
 * datacentre resolve to the same city and should collapse onto one line rather
 * than stacking ten identical arcs on top of each other, each drawn at full
 * opacity and summing into a solid streak.
 *
 * It is the key only. The rounded pair used to be stored as the route's
 * endpoints too, and drawn - which put every line up to half a kilometre from
 * the marker it was supposed to touch. At world zoom that is a fraction of a
 * pixel and invisible; zoomed in it is a line ending in open space beside its
 * own icon. Endpoints now carry the exact coordinates and only the grouping is
 * rounded.
 */
const KEY_PRECISION = 2;

/**
 * The most routes to draw.
 *
 * Aggregation is bounded by the packet buffer, but the number of distinct
 * *routes* is not - a port scan or a busy DNS resolver produces hundreds, and
 * past a certain count the map is a solid mesh that says less than ten lines
 * would. Sorted by traffic, so what is dropped is always the quietest.
 */
const MAX_ROUTES = 60;

/**
 * Tie-break order for the dominant protocol.
 *
 * Needed because argmax alone is unstable: a route carrying exactly as much
 * QUIC as TCP would pick whichever the iteration happened to reach first, and
 * recolour on every recount as packets arrive. A fixed order makes the colour a
 * function of the traffic rather than of timing.
 */
const TIE_BREAK: string[] = [
  'HTTP', 'HTTPS', 'TLS', 'QUIC', 'DNS', 'TCP', 'UDP', 'ICMP', 'ARP', 'SSH', 'MQTT', 'CUSTOM',
];

function rank(protocol: string): number {
  const i = TIE_BREAK.indexOf(protocol);
  return i === -1 ? TIE_BREAK.length : i;
}

function round(n: number): number {
  return Number(n.toFixed(KEY_PRECISION));
}

/** The protocol carrying the most packets, ties broken deterministically. */
export function dominantProtocol(counts: Record<string, number>): string {
  let best = '';
  let bestCount = -1;
  for (const [protocol, count] of Object.entries(counts)) {
    if (count > bestCount || (count === bestCount && rank(protocol) < rank(best))) {
      best = protocol;
      bestCount = count;
    }
  }
  return best;
}

/**
 * Groups a packet buffer into routes between places.
 *
 * `locate` is passed in rather than the location map itself, so this stays a
 * pure function of its inputs and the caller keeps ownership of what counts as
 * locatable - including the decision to anchor this machine's own traffic at
 * its public location.
 */
export function aggregateRoutes(
  packets: Packet[],
  locate: (ip: string) => LngLat | null,
): Route[] {
  const routes = new Map<string, Route>();

  for (const packet of packets) {
    const from = locate(packet.source);
    const to = locate(packet.destination);
    if (!from || !to) continue;

    const a = [round(from[0]), round(from[1])] as LngLat;
    const b = [round(to[0]), round(to[1])] as LngLat;
    // A packet between two hosts in the same place has no line to draw.
    if (a[0] === b[0] && a[1] === b[1]) continue;

    // Direction-independent: a request and its reply are one relationship, and
    // drawing them as two lines would double every conversation on the map.
    const forward = a[0] < b[0] || (a[0] === b[0] && a[1] < b[1]);
    const [lo, hi] = forward ? [a, b] : [b, a];
    const key = `${lo[0]},${lo[1]}|${hi[0]},${hi[1]}`;

    let route = routes.get(key);
    if (!route) {
      // The EXACT coordinates, ordered to match the key. Whichever packet
      // creates the route fixes the endpoints; every later packet in the same
      // rounded cell joins that line rather than nudging it, so a route does
      // not shiver as hosts a few hundred metres apart come and go.
      const [fromExact, toExact] = forward ? [from, to] : [to, from];
      route = { key, from: fromExact, to: toExact, counts: {}, total: 0, dominantProtocol: '' };
      routes.set(key, route);
    }
    const protocol = packet.protocol;
    route.counts[protocol] = (route.counts[protocol] ?? 0) + 1;
    route.total += 1;
  }

  const all = [...routes.values()];
  for (const route of all) route.dominantProtocol = dominantProtocol(route.counts);

  return all.sort((x, y) => y.total - x.total).slice(0, MAX_ROUTES);
}
