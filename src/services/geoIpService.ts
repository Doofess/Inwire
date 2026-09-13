/**
 * Turning an address seen on the wire into a place on the map.
 *
 * The rule this module exists to enforce: **never hand back a location the data
 * does not justify.** Everything below follows from that, and from the fact
 * that the previous version could not express it - it returned a bare
 * `GeoLocation | null`, where `null` meant "private" or "in flight" or "the
 * lookup failed", and a returned location carried no indication of whether the
 * provider had actually found the host or merely known which country it was in.
 *
 * Three consequences of that missing vocabulary, all of which showed up as
 * wrong pins on the map:
 *
 *   - **Country centroids looked like precise fixes.** A provider that can only
 *     place an address at country level answers with the country's centroid.
 *     Stripped of provenance, that is indistinguishable from a rooftop fix, so
 *     a host somewhere in the United States was pinned to a field in Kansas.
 *     `GeoPrecision` is the field that lets a caller refuse those.
 *   - **Addresses with no geography at all were looked up anyway.** The old
 *     classifier tested five prefixes; everything else was assumed routable.
 *     mDNS (224.0.0.251) and SSDP (239.255.255.250) are on virtually every
 *     network, so virtually every capture scattered pins for them.
 *   - **A single failure was permanent.** Any thrown error cached `null`
 *     forever, so one 429 from an unthrottled burst meant that host was never
 *     located again for the life of the page.
 */

/** How well the provider actually knows where this address is. */
export type GeoPrecision = 'city' | 'country';

export interface GeoLocation {
  ip: string;
  latitude: number;
  longitude: number;
  /** Null exactly when `precision` is 'country'. */
  city: string | null;
  region: string | null;
  country: string;
  countryCode: string;
  precision: GeoPrecision;
}

/**
 * What kind of address this is, and therefore whether it can have a location.
 *
 * Only `public` is ever sent to a provider. Everything else either has no
 * geography by definition (a LAN address, a multicast group) or is not an
 * address at all.
 */
export type IpClass =
  | 'public'
  | 'private'
  | 'loopback'
  | 'link-local'
  | 'cgnat'
  | 'multicast'
  | 'broadcast'
  | 'reserved'
  | 'invalid';

/**
 * The outcome of asking for a location, with the three failure modes kept
 * apart rather than collapsed into `null`. `failed` carries whether it is worth
 * asking again: a network blip is, "the provider has no data for this host" is
 * not.
 */
export type GeoResult =
  | { kind: 'resolved'; location: GeoLocation }
  | { kind: 'unlocatable'; class: Exclude<IpClass, 'public'> }
  | { kind: 'failed'; retryable: boolean };

// ---------------------------------------------------------------------------
// Address classification
// ---------------------------------------------------------------------------

/**
 * Strict dotted-quad parse.
 *
 * Strict because the loose `/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/` this
 * replaces accepted `999.999.999.999`, and because nothing validated that the
 * argument was an address at all before interpolating it into a request URL -
 * a hostname or the string `N/A` went straight into the query.
 */
function parseIPv4(ip: string): [number, number, number, number] | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    octets.push(n);
  }
  return octets as [number, number, number, number];
}

/**
 * Shape check rather than a full RFC 4291 parse: enough to reject a hostname
 * and keep a malformed string out of a URL, without reimplementing an address
 * parser for the sake of it. Classification below only ever reads the first
 * hextet, so precision beyond this buys nothing.
 */
function looksLikeIPv6(ip: string): boolean {
  if (!ip.includes(':')) return false;
  if (!/^[0-9a-f:.]+$/i.test(ip)) return false;
  if (ip.split('::').length - 1 > 1) return false;
  const groups = ip.split(':');
  if (groups.length > 8) return false;
  return groups.every(g => g === '' || /^[0-9a-f]{1,4}$/i.test(g) || parseIPv4(g) !== null);
}

/**
 * The leading 16 bits, which is all any IPv6 range below is defined by.
 * An address starting `::` has an empty head, which is zero.
 */
function firstHextet(ip: string): number {
  const head = ip.split('::')[0];
  const first = head.split(':')[0];
  if (first === '') return 0;
  const n = parseInt(first, 16);
  return Number.isNaN(n) ? 0 : n;
}

/**
 * Memoized classification results.
 *
 * Classification is a pure function of the string, so the answer for an address
 * never changes - which makes it exactly the kind of work that should be done
 * once per address rather than once per question.
 *
 * It matters because of how often the question is asked. `isLocatable` is
 * called from `locate` inside the geo map's route aggregation, which asks about
 * BOTH endpoints of EVERY packet on every recompute - 100,000 calls at the
 * 50,000-packet buffer cap, twice a second. Uncached, each of those parses the
 * string and runs a regex per octet.
 *
 * The set of distinct addresses in a capture is orders of magnitude smaller
 * than the number of packets, so the hit rate here is very close to 1.
 *
 * Bounded like the location cache above it and for the same reason: a long
 * capture on a busy link sees a lot of hosts. The entries are tiny (a string
 * and a short union member), so the cap is generous.
 */
const MAX_CLASS_CACHE = 20000;
const classCache = new Map<string, IpClass>();

/**
 * What kind of address this is.
 *
 * The ranges here are the whole point of the module: each one is a class of
 * address that has no location, and every one of them was previously looked up
 * as though it were an ordinary host.
 */
export function classifyIP(ip: string): IpClass {
  const hit = classCache.get(ip);
  if (hit !== undefined) return hit;
  const result = classifyIPUncached(ip);
  if (classCache.size >= MAX_CLASS_CACHE) {
    // Oldest first, matching `remember` above. Insertion order is close enough
    // to a usage order here that a real LRU is not worth the bookkeeping.
    const oldest = classCache.keys().next().value;
    if (oldest !== undefined) classCache.delete(oldest);
  }
  classCache.set(ip, result);
  return result;
}

function classifyIPUncached(ip: string): IpClass {
  const trimmed = ip.trim();
  if (!trimmed) return 'invalid';

  const v4 = parseIPv4(trimmed);
  if (v4) {
    const [a, b, c] = v4;

    if (trimmed === '255.255.255.255') return 'broadcast';
    if (a === 0) return 'reserved';
    if (a === 127) return 'loopback';
    if (a === 10) return 'private';
    if (a === 172 && b >= 16 && b <= 31) return 'private';
    if (a === 192 && b === 168) return 'private';
    if (a === 169 && b === 254) return 'link-local';
    // Carrier-grade NAT. Dangerous rather than merely useless: these often DO
    // resolve, to the carrier's registration address, so they produce a pin
    // that is confidently in the wrong place.
    if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
    if (a >= 224 && a <= 239) return 'multicast';
    if (a >= 240) return 'reserved';
    // Documentation, benchmark and relay ranges. They appear in captures more
    // often than their obscurity suggests - TEST-NET shows up in tutorials and
    // synthetic traffic, 6to4 in tunnelled IPv6.
    if (a === 192 && b === 0 && c === 2) return 'reserved';
    if (a === 198 && b === 51 && c === 100) return 'reserved';
    if (a === 203 && b === 0 && c === 113) return 'reserved';
    if (a === 198 && (b === 18 || b === 19)) return 'reserved';
    if (a === 192 && b === 88 && c === 99) return 'reserved';
    return 'public';
  }

  if (looksLikeIPv6(trimmed)) {
    if (trimmed === '::1') return 'loopback';
    if (trimmed === '::') return 'reserved';
    if (/^2001:0*db8:/i.test(trimmed)) return 'reserved';

    const head = firstHextet(trimmed);
    if ((head & 0xff00) === 0xff00) return 'multicast';
    if ((head & 0xffc0) === 0xfe80) return 'link-local';
    // fc00::/7. Real ULAs are almost always `fd..` - the `fc..` half was
    // reserved for a registry that never launched - so matching only the
    // literal `fc00` prefix, as an earlier version did, missed nearly all real
    // ULA traffic and sent it to the provider.
    if ((head & 0xfe00) === 0xfc00) return 'private';
    return 'public';
  }

  // Includes the app's own 'System' and 'Broadcast' sentinels, which stand in
  // for an address rather than being one.
  return 'invalid';
}

/** The single question every caller actually has. */
export function isLocatable(ip: string): boolean {
  return classifyIP(ip) === 'public';
}

// ---------------------------------------------------------------------------
// Provider response validation
// ---------------------------------------------------------------------------

function str(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

/**
 * Turns one provider record into a location, or rejects it.
 *
 * Everything here is a rejection the previous version did not make: it applied
 * `parseFloat` blindly and cached whatever came back, so a missing field became
 * `NaN` coordinates stored as a *successful* result, and the provider's
 * unknown-location sentinel of 0,0 became a pin in the Gulf of Guinea. The only
 * defence lived in the map component as `Math.abs(lat) > 0.1`, which also threw
 * away genuine locations near the prime meridian.
 *
 * `precision` is derived here rather than guessed downstream: a record with no
 * city is a country-level answer, whatever its coordinates look like.
 */
export function parseGeoResponse(ip: string, raw: unknown): GeoLocation | null {
  if (!raw || typeof raw !== 'object') return null;
  const data = raw as Record<string, unknown>;

  const latitude = Number(data.latitude);
  const longitude = Number(data.longitude);
  if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) return null;
  if (Math.abs(latitude) > 90 || Math.abs(longitude) > 180) return null;
  // Null Island. Tightened from the old 0.1° window - which is ~11km and
  // discarded real locations in Ghana and São Tomé - to a rounding tolerance.
  if (Math.abs(latitude) < 0.0001 && Math.abs(longitude) < 0.0001) return null;

  const city = str(data.city);
  const country = str(data.country_name) ?? str(data.country) ?? null;
  const countryCode = str(data.country_code) ?? str(data.country) ?? '';
  if (!country) return null;

  return {
    ip,
    latitude,
    longitude,
    city,
    region: str(data.region),
    country,
    countryCode,
    precision: city ? 'city' : 'country',
  };
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

/**
 * The two hosts this module talks to, named rather than written inline.
 *
 * They are behind **different** consent switches, which is the thing to get
 * right when reading this file: `GEO_ENDPOINT` is gated by
 * `nameResolution.geoIp`, `DOH_ENDPOINT` by `nameResolution.reverseDns`, and
 * they are two separate rows in Settings. Both send an address off this machine
 * - which makes "what does this app contact" a question somebody is entitled to
 * answer with one grep. The DoH URL used to be a template literal buried inside
 * `resolveHostname`, where it was findable only by knowing to look.
 */
const GEO_ENDPOINT = 'https://get.geojs.io/v1/ip/geo.json';

/** Cloudflare's DNS-over-HTTPS resolver, for reverse lookups. */
const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';

/**
 * How long to gather addresses before asking.
 *
 * The previous version fired one request per address from inside a loop over
 * newly-arrived packets, so a burst of new hosts produced a burst of
 * simultaneous requests - which is what earned the 429s that then poisoned the
 * cache permanently. A quarter of a second is below the map's own 500ms refresh,
 * so batching costs nothing visible.
 */
const BATCH_WINDOW_MS = 250;
const MAX_BATCH = 25;

/**
 * Bounded, because a long capture on a busy link sees a lot of hosts and this
 * used to be an unbounded Map that only grew.
 */
const MAX_CACHE = 5000;

const cache = new Map<string, GeoResult>();
/** One promise per address in flight, shared by every caller that asks for it. */
const inflight = new Map<string, Promise<GeoResult>>();
const settle = new Map<string, (result: GeoResult) => void>();
let queue: string[] = [];
let queueTimer: ReturnType<typeof setTimeout> | null = null;

function remember(ip: string, result: GeoResult): void {
  // A retryable failure is deliberately not remembered: that is the whole
  // difference from the version where one network blip was final.
  if (result.kind === 'failed' && result.retryable) return;
  if (cache.size >= MAX_CACHE) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(ip, result);
}

function finish(ip: string, result: GeoResult): void {
  remember(ip, result);
  settle.get(ip)?.(result);
  settle.delete(ip);
  inflight.delete(ip);
}

async function flushQueue(): Promise<void> {
  queueTimer = null;
  const batch = queue.slice(0, MAX_BATCH);
  queue = queue.slice(MAX_BATCH);
  // Anything left over goes in the next window rather than being dropped.
  if (queue.length > 0) scheduleFlush();
  if (batch.length === 0) return;

  try {
    const res = await fetch(`${GEO_ENDPOINT}?ip=${batch.join(',')}`);
    if (!res.ok) throw new Error(`geo lookup failed: ${res.status}`);
    const payload = await res.json();
    const records: unknown[] = Array.isArray(payload) ? payload : [payload];

    const byIp = new Map<string, unknown>();
    for (const record of records) {
      const recordIp = str((record as Record<string, unknown>)?.ip);
      if (recordIp) byIp.set(recordIp, record);
    }

    for (const ip of batch) {
      const record = byIp.get(ip);
      const location = record ? parseGeoResponse(ip, record) : null;
      // No record, or one that failed validation, means the provider has
      // nothing usable for this host. Not worth asking again.
      finish(ip, location ? { kind: 'resolved', location } : { kind: 'failed', retryable: false });
    }
  } catch {
    // Network-level: the address is fine, the request was not. Left uncached so
    // a later attempt can succeed.
    for (const ip of batch) finish(ip, { kind: 'failed', retryable: true });
  }
}

function scheduleFlush(): void {
  if (queueTimer !== null) return;
  queueTimer = setTimeout(() => { void flushQueue(); }, BATCH_WINDOW_MS);
}

/**
 * Where this address is, if it is anywhere.
 *
 * Concurrent callers for the same address share one promise and one request,
 * rather than the second caller being told `null` because the first had it in
 * flight - which read as "unresolvable" and, combined with the map asking only
 * once per address, meant it was never resolved at all.
 */
export function resolveIP(ip: string): Promise<GeoResult> {
  const cached = cache.get(ip);
  if (cached) return Promise.resolve(cached);

  // Gated BEFORE the cache is written, and returning a retryable failure on
  // purpose. Writing "unlocatable" here would poison the cache with an answer
  // that is about the setting rather than about the address, and re-enabling
  // the lookup would then resolve nothing until the page was reloaded - which
  // is the permanent-negative-cache bug this module was rewritten to remove.
  if (!nameResolution.geoIp) return Promise.resolve({ kind: 'failed', retryable: true });

  const cls = classifyIP(ip);
  if (cls !== 'public') {
    const result: GeoResult = { kind: 'unlocatable', class: cls };
    remember(ip, result);
    return Promise.resolve(result);
  }

  const existing = inflight.get(ip);
  if (existing) return existing;

  const promise = new Promise<GeoResult>(resolve => { settle.set(ip, resolve); });
  inflight.set(ip, promise);
  queue.push(ip);
  scheduleFlush();
  return promise;
}

/** Test seam. Not used by the app. */
export function resetGeoCacheForTests(): void {
  classCache.clear();
  selfLocationPromise = null;
  cache.clear();
  inflight.clear();
  settle.clear();
  queue = [];
  if (queueTimer !== null) {
    clearTimeout(queueTimer);
    queueTimer = null;
  }
}

// ---------------------------------------------------------------------------
// What is allowed to leave this machine
// ---------------------------------------------------------------------------

/**
 * Whether the two outbound lookups are permitted.
 *
 * Both are off until something turns them on. The data they send is not
 * preference data - it is a derived list of who a network has been talking to,
 * and for an imported capture it is a list belonging to somebody else - so
 * launching a packet analyser is not consent to publish it.
 *
 * The failure mode decides this as much as the principle does. `savePreference`
 * swallows write failures by design, so with an opt-OUT default a blocked or
 * full localStorage means a user's "off" silently reverts on next load and the
 * lookups resume, invisibly, after they declined. Opt-in fails the other way:
 * an empty map, which is visible and fixable.
 *
 * Held here rather than checked at each call site because there are three
 * resolvers and more callers than that, and a gate you have to remember to
 * apply is one that eventually is not.
 */
export interface NameResolutionOptions {
  geoIp: boolean;
  reverseDns: boolean;
}

const NAME_RESOLUTION_OFF: NameResolutionOptions = { geoIp: false, reverseDns: false };

let nameResolution: NameResolutionOptions = { ...NAME_RESOLUTION_OFF };

/** Notified when a lookup is switched ON, so callers can retry what they skipped. */
const resolutionListeners = new Set<() => void>();

export function onNameResolutionEnabled(listener: () => void): () => void {
  resolutionListeners.add(listener);
  return () => {
    resolutionListeners.delete(listener);
  };
}

export function setNameResolutionOptions(next: NameResolutionOptions): void {
  const enabling =
    (next.geoIp && !nameResolution.geoIp) || (next.reverseDns && !nameResolution.reverseDns);
  const disablingGeo = !next.geoIp && nameResolution.geoIp;
  const disablingDns = !next.reverseDns && nameResolution.reverseDns;
  nameResolution = { ...next };

  // Turning a lookup off clears what it learned. Leaving the answers cached
  // would mean the map kept displaying locations derived from addresses the
  // user has just said should not have been sent anywhere.
  if (disablingGeo) {
    cache.clear();
    selfLocationPromise = null;
  }
  if (disablingDns) hostnameCache.clear();

  // Turning one on has to invalidate the callers' own "already asked" records,
  // or nothing already in the buffer is ever looked up and the feature appears
  // not to work until the buffer is cleared.
  if (enabling) for (const listener of resolutionListeners) listener();
}

export function getNameResolutionOptions(): NameResolutionOptions {
  return nameResolution;
}

/** Test seam, alongside resetGeoCacheForTests. */
export function resetNameResolutionForTests(): void {
  nameResolution = { ...NAME_RESOLUTION_OFF };
  resolutionListeners.clear();
}

// ---------------------------------------------------------------------------
// This machine's own location
// ---------------------------------------------------------------------------

/**
 * The one lookup that is about the user rather than about their traffic.
 *
 * The endpoint carries no address, so the provider geolocates the requesting
 * socket - it answers "where is the machine asking?". That makes it the most
 * sensitive request the app makes, and it is the reason it lives here rather
 * than as a bare `fetch` in a component: anything that gates outbound lookups
 * has to be able to reach it, and a call site inside a `useEffect` is reachable
 * only by whoever remembers it exists.
 *
 * Memoized as a promise, not as a value, so that concurrent callers share one
 * request and - more importantly - so that a component unmounting and
 * remounting does not re-ask. The geo map is unmounted whenever the dashboard
 * is minimized, and without this every toggle of that control would be another
 * request to a third-party geolocation service.
 *
 * A failure is not memoized: the promise is cleared so the next caller retries,
 * which matches how a retryable failure is handled for ordinary lookups.
 */
let selfLocationPromise: Promise<GeoLocation | null> | null = null;

export function resolveSelfLocation(): Promise<GeoLocation | null> {
  // The same switch. This is the request that asks a third party where the
  // USER is, rather than where their traffic is going, so if anything is gated
  // it is this.
  if (!nameResolution.geoIp) return Promise.resolve(null);
  if (selfLocationPromise) return selfLocationPromise;
  selfLocationPromise = fetch(GEO_ENDPOINT)
    .then((res) => res.json())
    .then((data) => {
      // Validated through the same parser as every other lookup rather than
      // trusted because it is ours: this used to write parseFloat output
      // straight into state, so a bad response put NaN coordinates on the one
      // marker every connection line is anchored to.
      return parseGeoResponse(String((data as { ip?: unknown })?.ip ?? 'self'), data);
    })
    .catch((err) => {
      console.error('Failed to fetch ISP location', err);
      selfLocationPromise = null;
      return null;
    });
  return selfLocationPromise;
}

// ---------------------------------------------------------------------------
// Reverse DNS
// ---------------------------------------------------------------------------

const hostnameCache = new Map<string, string | null>();
const hostnamePending = new Set<string>();

/**
 * Reverse-DNS (PTR) lookup via Cloudflare's public DNS-over-HTTPS resolver -
 * free, no API key, CORS-enabled. Only IPv4 is supported (IPv6 PTR requires
 * nibble-expanding the address into ip6.arpa, and most captured IPv6 traffic
 * has no PTR record anyway). Many IPs simply have no reverse DNS configured,
 * so a null result is the expected common case, not an error.
 */
export const resolveHostname = async (ip: string): Promise<string | null> => {
  if (hostnameCache.has(ip)) return hostnameCache.get(ip)!;
  // Nothing cached on the way out, for the same reason as above.
  if (!nameResolution.reverseDns) return null;
  if (hostnamePending.has(ip) || !isLocatable(ip) || parseIPv4(ip) === null) return null;

  hostnamePending.add(ip);
  try {
    const reversed = ip.split('.').reverse().join('.');
    const res = await fetch(
      `${DOH_ENDPOINT}?name=${reversed}.in-addr.arpa&type=PTR`,
      { headers: { accept: 'application/dns-json' } },
    );
    if (!res.ok) throw new Error('DoH request failed');
    const data = await res.json();
    const hostname: string | undefined = data?.Answer?.[0]?.data;
    const clean = hostname ? hostname.replace(/\.$/, '') : null;
    hostnameCache.set(ip, clean);
    hostnamePending.delete(ip);
    return clean;
  } catch {
    hostnameCache.set(ip, null);
    hostnamePending.delete(ip);
    return null;
  }
};
