export interface GeoLocation {
  ip: string;
  latitude: number;
  longitude: number;
  city: string;
  country: string;
}

const cache = new Map<string, GeoLocation | null>();
const pending = new Set<string>();

const hostnameCache = new Map<string, string | null>();
const hostnamePending = new Set<string>();

const isIPv4 = (ip: string) => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip);

/**
 * Reverse-DNS (PTR) lookup via Cloudflare's public DNS-over-HTTPS resolver -
 * free, no API key, CORS-enabled. Only IPv4 is supported (IPv6 PTR requires
 * nibble-expanding the address into ip6.arpa, and most captured IPv6 traffic
 * has no PTR record anyway). Many IPs simply have no reverse DNS configured,
 * so a null result is the expected common case, not an error.
 */
export const resolveHostname = async (ip: string): Promise<string | null> => {
  if (hostnameCache.has(ip)) return hostnameCache.get(ip)!;
  if (hostnamePending.has(ip) || !isIPv4(ip) || isPrivateIP(ip)) return null;

  hostnamePending.add(ip);
  try {
    const reversed = ip.split('.').reverse().join('.');
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${reversed}.in-addr.arpa&type=PTR`,
      { headers: { accept: 'application/dns-json' } }
    );
    if (!res.ok) throw new Error('DoH request failed');
    const data = await res.json();
    const hostname: string | undefined = data?.Answer?.[0]?.data;
    const clean = hostname ? hostname.replace(/\.$/, '') : null;
    hostnameCache.set(ip, clean);
    hostnamePending.delete(ip);
    return clean;
  } catch (e) {
    hostnameCache.set(ip, null);
    hostnamePending.delete(ip);
    return null;
  }
};

export const isPrivateIP = (ip: string) => {
  if (ip === 'System' || ip === 'Broadcast') return true;
  // IPv4 private ranges (10.x.x.x, 192.168.x.x, 172.16-31.x.x, 127.x.x.x)
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|0\.)/.test(ip)) return true;
  // IPv6 loopback/unspecified
  if (ip === '::1' || ip === '::') return true;
  // IPv6 link-local (fe80::/10, i.e. fe80-febf) and Unique Local Addresses
  // (fc00::/7, i.e. fc00-fdff). Real-world ULAs are almost always "fd..."
  // (the "fc.." half of the range was reserved for a global registry that
  // never launched) - matching only the literal "fc00" prefix (as this
  // check previously did) misses virtually all real ULA traffic, which
  // then gets treated as a public IP and sent to the geolocation API,
  // producing nonsense scattered map pins for addresses with no real
  // geographic meaning.
  if (/^(fe[89ab][0-9a-f]:|f[cd][0-9a-f]{2}:)/i.test(ip)) return true;
  return false;
};

export const resolveIP = async (ip: string): Promise<GeoLocation | null> => {
  if (cache.has(ip)) return cache.get(ip)!;
  if (pending.has(ip) || isPrivateIP(ip)) return null;

  pending.add(ip);
  try {
    const res = await fetch(`https://get.geojs.io/v1/ip/geo/${ip}.json`);
    if (!res.ok) throw new Error('Failed to fetch');
    const data = await res.json();
    
    const loc: GeoLocation = {
      ip,
      latitude: parseFloat(data.latitude),
      longitude: parseFloat(data.longitude),
      city: data.city || 'Unknown',
      country: data.country || 'Unknown'
    };
    cache.set(ip, loc);
    pending.delete(ip);
    return loc;
  } catch (e) {
    // Avoid re-querying failed IPs immediately by setting to null in cache
    cache.set(ip, null); 
    pending.delete(ip);
    return null;
  }
};
