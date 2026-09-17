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

// Arithmetic, not `Number(n.toFixed(...))`: that allocates and parses a
// string, and this runs four times per located packet on every aggregation.
const KEY_SCALE = 10 ** KEY_PRECISION;
function round(n: number): number {
  return Math.round(n * KEY_SCALE) / KEY_SCALE;
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
 * Traffic between two addresses, before anything is known about where they are.
 *
 * The split between this and `aggregateRoutes` is what lets the map keep up
 * with a live capture. Counting packets per address pair does not depend on
 * geography at all, so it can be folded one packet at a time and kept across
 * ticks; turning pairs into lines does depend on geography, and geography
 * arrives late and out of order, as lookups come back for addresses whose
 * packets went by seconds ago.
 *
 * Folding both together meant either re-reading the whole buffer every tick or
 * silently missing every route whose location resolved after its packets had
 * been counted. Separated, the expensive half is incremental and the half that
 * has to be redone when a lookup lands is bounded by how many pairs are
 * talking rather than by how long the capture has been running.
 */
export interface AddressPair {
  source: string;
  destination: string;
  /** Packets seen per protocol, which is what `dominantProtocol` argmaxes. */
  counts: Record<string, number>;
  total: number;
}

/**
 * The key `addPacketToPairs` files a packet under. Direction is kept here.
 *
 * `>` is the separator because it cannot occur in either half: these are
 * addresses as the dissector renders them - dotted quads, colon-separated IPv6
 * and MAC addresses, and resolved OUI names - and none of those can contain it.
 */
function pairKey(source: string, destination: string): string {
  return `${source}>${destination}`;
}

/**
 * Folds one packet into a pair map, in place.
 *
 * Direction is NOT canonicalised here, unlike in the route key below. Two
 * addresses in one city collapse onto a single line whichever way round they
 * are, and that merge happens in `aggregateRoutes` where the coordinates are
 * known - so doing it here as well would only hide which address was which
 * from a caller that might want it.
 */
export function addPacketToPairs(pairs: Map<string, AddressPair>, packet: Packet): void {
  if (!packet.source || !packet.destination) return;
  const key = pairKey(packet.source, packet.destination);
  let pair = pairs.get(key);
  if (!pair) {
    pair = { source: packet.source, destination: packet.destination, counts: {}, total: 0 };
    pairs.set(key, pair);
  }
  pair.counts[packet.protocol] = (pair.counts[packet.protocol] ?? 0) + 1;
  pair.total += 1;
}

/**
 * Groups address pairs into routes between places.
 *
 * `locate` is passed in rather than the location map itself, so this stays a
 * pure function of its inputs and the caller keeps ownership of what counts as
 * locatable - including the decision to anchor this machine's own traffic at
 * its public location.
 */
export function aggregateRoutes(
  pairs: Iterable<AddressPair>,
  locate: (ip: string) => LngLat | null,
): Route[] {
  const routes = new Map<string, Route>();

  for (const pair of pairs) {
    const from = locate(pair.source);
    const to = locate(pair.destination);
    if (!from || !to) continue;

    const a = [round(from[0]), round(from[1])] as LngLat;
    const b = [round(to[0]), round(to[1])] as LngLat;
    // Traffic between two hosts in the same place has no line to draw.
    if (a[0] === b[0] && a[1] === b[1]) continue;

    // Direction-independent: a request and its reply are one relationship, and
    // drawing them as two lines would double every conversation on the map.
    const forward = a[0] < b[0] || (a[0] === b[0] && a[1] < b[1]);
    const [lo, hi] = forward ? [a, b] : [b, a];
    const key = `${lo[0]},${lo[1]}|${hi[0]},${hi[1]}`;

    let route = routes.get(key);
    if (!route) {
      // The EXACT coordinates, ordered to match the key. Whichever pair
      // creates the route fixes the endpoints; every later pair in the same
      // rounded cell joins that line rather than nudging it, so a route does
      // not shiver as hosts a few hundred metres apart come and go.
      const [fromExact, toExact] = forward ? [from, to] : [to, from];
      route = { key, from: fromExact, to: toExact, counts: {}, total: 0, dominantProtocol: '' };
      routes.set(key, route);
    }
    for (const protocol in pair.counts) {
      route.counts[protocol] = (route.counts[protocol] ?? 0) + pair.counts[protocol];
    }
    route.total += pair.total;
  }

  const all = [...routes.values()];
  for (const route of all) route.dominantProtocol = dominantProtocol(route.counts);

  return all.sort((x, y) => y.total - x.total).slice(0, MAX_ROUTES);
}

/**
 * One located place on the map, aggregated across every host that resolved to it.
 *
 * Lived in `GeoLocationCounter.tsx` until that component was deleted - it drew a
 * floating "11 LOCATIONS" pill over the card, which stopped having a reason to
 * exist the moment the pane grew a title bar with the count in it. The type
 * outlived the pill because `GeoMap`'s `geoStats` and its expanded side panel
 * are both built out of it, so it moved here, beside the route aggregation it
 * sits next to in the data flow.
 */
export interface GeoPlace {
  /**
   * Stable identity across the session: rounded `lat,lon` for a city-level
   * place, the country code for a country-level one - so every host the
   * provider could only put in Germany collapses to a single Germany row rather
   * than one per address.
   */
  key: string;
  latitude: number;
  longitude: number;
  /** The city, or the country when that is as precise as the lookup got. */
  label: string;
  country: string;
  countryCode: string;
  /** Distinct addresses resolved to this place so far. */
  hosts: number;
  /**
   * `country` rows are listed but never plotted.
   *
   * A country-level answer is the provider's centroid for the whole country - a
   * real coordinate, but not this host's - so drawing it would put a pin in a
   * field in Kansas and give it the same weight as a real fix. That is the
   * accuracy rule the map is built on and it does not change. What changes is
   * that these are no longer reported as a bare count of things withheld: "31
   * hidden" tells you nothing you can act on, while "Germany, 4 hosts" is the
   * actual answer to where the traffic went, just at a coarser resolution than
   * the map can honestly draw.
   */
  precision: 'city' | 'country';
}
