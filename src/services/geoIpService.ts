export interface GeoLocation {
  ip: string;
  latitude: number;
  longitude: number;
  city: string;
  country: string;
}

const cache = new Map<string, GeoLocation | null>();
const pending = new Set<string>();

export const isPrivateIP = (ip: string) => {
  if (ip === 'System' || ip === 'Broadcast') return true;
  // Private IPs (10.x.x.x, 192.168.x.x, 172.16-31.x.x, 127.x.x.x)
  return /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|0\.|::|fe80|fc00)/.test(ip);
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
